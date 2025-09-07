/* ======================================================================

  Telecom Revenue Protection — Advanced Anomaly Detection (BigQuery)

  Purpose: Flag over/under-billing, missing bills, usage/proration errors,

           and discount/tax mismatches with a confidence score.

  NOTE: Works with de-identified/sample data. Adjust table/column names.



-- =========================

WITH params AS (

  SELECT

    DATE_TRUNC(CURRENT_DATE(), MONTH)                             AS asof_month,

    CAST(0.12 AS NUMERIC)                                         AS pct_tolerance,       -- ±12% wiggle room vs expected

    CAST(2.25 AS NUMERIC)                                         AS z_thresh,            -- z-score threshold for outliers

    5                                                             AS min_months_for_stats -- need history to compute z-scores

),




-- ======================================================

-- Month spine: last 12 months including current month

-- ======================================================

months AS (

  SELECT month_start

  FROM UNNEST(

    GENERATE_DATE_ARRAY(

      DATE_SUB(DATE_TRUNC(CURRENT_DATE(), MONTH), INTERVAL 11 MONTH),

      DATE_TRUNC(CURRENT_DATE(), MONTH),

      INTERVAL 1 MONTH

    )

  ) AS month_start

),




-- ======================================================

-- Customer x Month grid

-- ======================================================

cust_month AS (

  SELECT c.customer_id, m.month_start AS bill_month

  FROM customers c

  CROSS JOIN months m

),




-- ======================================================

-- Normalize plan windows to [from, to) to avoid off-by-one issues

-- plan_history(effective_from, effective_to) where effective_to may be NULL

-- ======================================================

plan_in_effect AS (

  SELECT

    cm.customer_id,

    cm.bill_month                                   AS month_start,

    DATE_ADD(cm.bill_month, INTERVAL 1 MONTH)       AS month_end_excl,

    ph.plan_id,

    p.monthly_rate,

    GREATEST(CAST(ph.effective_from AS DATE), cm.bill_month)                        AS active_from,

    LEAST(CAST(IFNULL(ph.effective_to, DATE '2999-12-31') AS DATE),

          DATE_ADD(cm.bill_month, INTERVAL 1 MONTH))                                 AS active_to_excl

  FROM cust_month cm

  JOIN plan_history ph

    ON ph.customer_id = cm.customer_id

   AND CAST(ph.effective_from AS DATE) < DATE_ADD(cm.bill_month, INTERVAL 1 MONTH)

   AND CAST(IFNULL(ph.effective_to, DATE '2999-12-31') AS DATE) > cm.bill_month

  JOIN plans p ON p.plan_id = ph.plan_id

),




-- ======================================================

-- Proration counts using exclusive end bounds

-- ======================================================

plan_proration AS (

  SELECT

    customer_id,

    month_start AS bill_month,

    plan_id,

    monthly_rate,

    active_from,

    active_to_excl,

    -- active day count within the month (exclusive end)

    DATE_DIFF(active_to_excl, active_from, DAY)                         AS active_days,

    -- month day count (exclusive end)

    DATE_DIFF(DATE_ADD(month_start, INTERVAL 1 MONTH), month_start, DAY) AS days_in_month

  FROM plan_in_effect

),




expected_recurring AS (

  SELECT

    customer_id,

    bill_month,

    plan_id,

    -- prorated base charge (no early rounding)

    monthly_rate * SAFE_DIVIDE(CAST(active_days AS NUMERIC), NULLIF(days_in_month, 0)) AS expected_base_charge

  FROM plan_proration

),




-- ======================================================

-- Expected usage charges (logic)

-- usage(customer_id, usage_date, units, unit_type)

-- plans has columns: included_units, overage_rate (simplified single bucket)

-- ======================================================

usage_month AS (

  SELECT

    u.customer_id,

    DATE_TRUNC(CAST(u.usage_date AS DATE), MONTH) AS bill_month,

    SUM(u.units)                                  AS units_used

  FROM usage u

  JOIN months m

    ON DATE_TRUNC(CAST(u.usage_date AS DATE), MONTH) = m.month_start

  GROUP BY 1,2

),




plan_allowance AS (

  SELECT

    e.customer_id,

    e.bill_month,

    e.plan_id,

    p.included_units,

    p.overage_rate,

    IFNULL(u.units_used, 0) AS units_used

  FROM expected_recurring e

  JOIN plans p ON p.plan_id = e.plan_id

  LEFT JOIN usage_month u

    ON u.customer_id = e.customer_id AND u.bill_month = e.bill_month

),




expected_usage AS (

  SELECT

    customer_id,

    bill_month,

    GREATEST(units_used - included_units, 0) * CAST(overage_rate AS NUMERIC) AS expected_usage_charge

  FROM plan_allowance

),




-- ======================================================

-- Expected discounts and taxes/fees (rules)

-- discounts(customer_id, bill_month, amount) -> negative numbers

-- taxes_fees(customer_id, bill_month, amount) -> positive numbers

-- ======================================================

expected_discounts AS (

  SELECT d.customer_id,

         d.bill_month,

         CAST(IFNULL(SUM(d.amount), 0) AS NUMERIC) AS expected_discounts

  FROM discounts d

  JOIN months m ON d.bill_month = m.month_start

  GROUP BY 1,2

),

expected_taxes AS (

  SELECT t.customer_id,

         t.bill_month,

         CAST(IFNULL(SUM(t.amount), 0) AS NUMERIC) AS expected_taxes_fees

  FROM taxes_fees t

  JOIN months m ON t.bill_month = m.month_start

  GROUP BY 1,2

),




-- ======================================================

-- Expected total per customer-month

-- ======================================================

expected_total AS (

  SELECT

    e.customer_id,

    e.bill_month,

    e.expected_base_charge,

    IFNULL(u.expected_usage_charge, 0) AS expected_usage_charge,

    IFNULL(d.expected_discounts, 0)    AS expected_discounts,

    IFNULL(t.expected_taxes_fees, 0)   AS expected_taxes_fees,

    (e.expected_base_charge

     + IFNULL(u.expected_usage_charge, 0)

     + IFNULL(t.expected_taxes_fees, 0)

     + IFNULL(d.expected_discounts, 0)) AS expected_total_charge

  FROM expected_recurring e

  LEFT JOIN expected_usage     u ON u.customer_id = e.customer_id AND u.bill_month = e.bill_month

  LEFT JOIN expected_discounts d ON d.customer_id = e.customer_id AND d.bill_month = e.bill_month

  LEFT JOIN expected_taxes     t ON t.customer_id = e.customer_id AND t.bill_month = e.bill_month

),




-- ======================================================

-- Actual billed totals from billing_lines

-- billing_lines(customer_id, bill_month, line_type, amount, bill_id)

-- line_type in ('base','usage','discount','tax','fee','other')

-- ======================================================

billed AS (

  SELECT

    bl.customer_id,

    CAST(bl.bill_month AS DATE)                                      AS bill_month,

    CAST(SUM(bl.amount) AS NUMERIC)                                  AS actual_total_charge,

    CAST(SUM(IF(bl.line_type = 'base',        bl.amount, 0)) AS NUMERIC) AS actual_base,

    CAST(SUM(IF(bl.line_type = 'usage',       bl.amount, 0)) AS NUMERIC) AS actual_usage,

    CAST(SUM(IF(bl.line_type = 'discount',    bl.amount, 0)) AS NUMERIC) AS actual_discount,

    CAST(SUM(IF(bl.line_type IN ('tax','fee'),bl.amount, 0)) AS NUMERIC) AS actual_taxes_fees,

    COUNT(DISTINCT bl.bill_id)                                       AS bill_count

  FROM billing_lines bl

  JOIN months m ON CAST(bl.bill_month AS DATE) = m.month_start

  GROUP BY 1,2

),




-- ======================================================

-- Combine expectations vs actuals + allowance context

-- ======================================================

compare AS (

  SELECT

    x.customer_id,

    x.bill_month,

    x.expected_base_charge,

    x.expected_usage_charge,

    x.expected_discounts,

    x.expected_taxes_fees,

    x.expected_total_charge,

    IFNULL(b.actual_total_charge, 0) AS actual_total_charge,

    IFNULL(b.actual_base, 0)         AS actual_base,

    IFNULL(b.actual_usage, 0)        AS actual_usage,

    IFNULL(b.actual_discount, 0)     AS actual_discount,

    IFNULL(b.actual_taxes_fees, 0)   AS actual_taxes_fees,

    IFNULL(b.bill_count, 0)          AS bill_count,

    -- allowance context

    IFNULL(pa.units_used, 0)         AS units_used,

    pa.included_units,

    pa.overage_rate

  FROM expected_total x

  LEFT JOIN billed b

    ON b.customer_id = x.customer_id AND b.bill_month = x.bill_month

  LEFT JOIN plan_allowance pa

    ON pa.customer_id = x.customer_id AND pa.bill_month = x.bill_month

),




-- ======================================================

-- Deviation metrics and categorical reasons

-- ======================================================

diffs AS (

  SELECT

    c.*,

    CASE

      WHEN c.expected_total_charge = 0 AND c.actual_total_charge = 0 THEN 0

      WHEN c.expected_total_charge = 0 AND c.actual_total_charge <> 0 THEN 9999 -- sentinel for unexpected charges

      ELSE SAFE_DIVIDE(c.actual_total_charge - c.expected_total_charge, c.expected_total_charge)

    END AS pct_diff,

    CASE

      WHEN bill_count = 0 THEN 'MISSING_BILL'

      WHEN bill_count > 1 THEN 'DUPLICATE_BILL'

      WHEN c.expected_total_charge = 0 AND c.actual_total_charge <> 0 THEN 'UNEXPECTED_BILL'

      WHEN c.units_used <= IFNULL(c.included_units, 0) AND c.actual_usage > 0 THEN 'ALLOWANCE_MISMATCH'

      WHEN ABS(c.actual_base - c.expected_base_charge)      > GREATEST(2, ABS(c.expected_base_charge)   * (SELECT pct_tolerance FROM params)) THEN 'BASE_PRORATION_MISMATCH'

      WHEN ABS(c.actual_usage - c.expected_usage_charge)    > GREATEST(2, ABS(c.expected_usage_charge)  * (SELECT pct_tolerance FROM params)) THEN 'USAGE_MISMATCH'

      WHEN ABS(c.actual_discount - c.expected_discounts)    > GREATEST(2, ABS(c.expected_discounts)     * (SELECT pct_tolerance FROM params)) THEN 'DISCOUNT_MISMATCH'

      WHEN ABS(c.actual_taxes_fees - c.expected_taxes_fees) > GREATEST(2, ABS(c.expected_taxes_fees)    * (SELECT pct_tolerance FROM params)) THEN 'TAX_FEE_MISMATCH'

      WHEN c.actual_total_charge > c.expected_total_charge * (1 + (SELECT pct_tolerance FROM params)) THEN 'OVER_BILLED'

      WHEN c.actual_total_charge < c.expected_total_charge * (1 - (SELECT pct_tolerance FROM params)) THEN 'UNDER_BILLED'

      ELSE NULL

    END AS anomaly_reason

  FROM compare c

),




-- ======================================================

-- Z-scores on customer history (leave-one-out)

-- Use full billing history for stability

-- ======================================================

stats_base AS (

  SELECT

    customer_id,

    CAST(bill_month AS DATE) AS bill_month,

    actual_total_charge,

    AVG(actual_total_charge) OVER (

      PARTITION BY customer_id ORDER BY bill_month

      ROWS BETWEEN 12 PRECEDING AND 1 PRECEDING

    ) AS mean_12m,

    STDDEV_SAMP(actual_total_charge) OVER (

      PARTITION BY customer_id ORDER BY bill_month

      ROWS BETWEEN 12 PRECEDING AND 1 PRECEDING

    ) AS sd_12m,

    COUNT(actual_total_charge) OVER (

      PARTITION BY customer_id ORDER BY bill_month

      ROWS BETWEEN 12 PRECEDING AND 1 PRECEDING

    ) AS n_12m

  FROM (

    SELECT bl.customer_id,

           CAST(bl.bill_month AS DATE)                  AS bill_month,

           CAST(SUM(bl.amount) AS NUMERIC)              AS actual_total_charge

    FROM billing_lines bl

    GROUP BY 1,2

  ) agg

),




zcalc AS (

  SELECT

    d.*,

    s.mean_12m,

    s.sd_12m,

    s.n_12m,

    CASE

      WHEN s.sd_12m IS NULL OR s.sd_12m = 0 OR s.n_12m < (SELECT min_months_for_stats FROM params)

        THEN NULL

      ELSE SAFE_DIVIDE(d.actual_total_charge - s.mean_12m, s.sd_12m)

    END AS z_score

  FROM diffs d

  LEFT JOIN stats_base s

    ON s.customer_id = d.customer_id AND s.bill_month = d.bill_month

),




-- ======================================================

-- Confidence score blends rule-based and statistical signals (capped at 1.0)

-- ======================================================

scored AS (

  SELECT

    *,

    LEAST(

      CASE anomaly_reason

        WHEN 'MISSING_BILL'            THEN 0.95

        WHEN 'DUPLICATE_BILL'          THEN 0.90

        WHEN 'UNEXPECTED_BILL'         THEN 0.85

        WHEN 'ALLOWANCE_MISMATCH'      THEN 0.82

        WHEN 'BASE_PRORATION_MISMATCH' THEN 0.80

        WHEN 'USAGE_MISMATCH'          THEN 0.80

        WHEN 'DISCOUNT_MISMATCH'       THEN 0.75

        WHEN 'TAX_FEE_MISMATCH'        THEN 0.70

        WHEN 'OVER_BILLED'             THEN 0.65

        WHEN 'UNDER_BILLED'            THEN 0.65

        ELSE 0.00

      END

      + CASE WHEN ABS(IFNULL(z_score, 0)) >= (SELECT z_thresh FROM params) THEN 0.25 ELSE 0 END

    , 1.0) AS confidence_score

  FROM zcalc

)




SELECT

  customer_id,

  bill_month,

  ROUND(expected_total_charge, 2) AS expected_total_charge,

  ROUND(actual_total_charge, 2)   AS actual_total_charge,

  ROUND(CASE WHEN pct_diff = 9999 THEN 100.00

             ELSE IFNULL(pct_diff, 0) * 100 END, 2) AS pct_diff_pct,

  anomaly_reason,

  ROUND(IFNULL(z_score, 0), 2)    AS z_score,

  ROUND(confidence_score, 2)      AS confidence_score,




  -- Components (rounded only at projection)

  ROUND(expected_base_charge, 2)   AS expected_base_charge,

  ROUND(actual_base, 2)            AS actual_base,

  ROUND(expected_usage_charge, 2)  AS expected_usage_charge,

  ROUND(actual_usage, 2)           AS actual_usage,

  ROUND(expected_discounts, 2)     AS expected_discounts,

  ROUND(actual_discount, 2)        AS actual_discount,

  ROUND(expected_taxes_fees, 2)    AS expected_taxes_fees,

  ROUND(actual_taxes_fees, 2)      AS actual_taxes_fees,

  bill_count,




  -- Quick triage: component deltas (%)

  ROUND(

    CASE WHEN expected_base_charge = 0 THEN NULL

         ELSE SAFE_DIVIDE(actual_base - expected_base_charge, expected_base_charge) * 100 END

  , 2) AS pct_diff_base,

  ROUND(

    CASE WHEN expected_usage_charge = 0 THEN NULL

         ELSE SAFE_DIVIDE(actual_usage - expected_usage_charge, expected_usage_charge) * 100 END

  , 2) AS pct_diff_usage,

  ROUND(

    CASE WHEN expected_discounts = 0 THEN NULL

         ELSE SAFE_DIVIDE(actual_discount - expected_discounts, expected_discounts) * 100 END

  , 2) AS pct_diff_discount,

  ROUND(

    CASE WHEN expected_taxes_fees = 0 THEN NULL

         ELSE SAFE_DIVIDE(actual_taxes_fees - expected_taxes_fees, expected_taxes_fees) * 100 END

  , 2) AS pct_diff_tax




FROM scored

WHERE anomaly_reason IS NOT NULL

   OR ABS(IFNULL(z_score, 0)) >= (SELECT z_thresh FROM params)

ORDER BY confidence_score DESC, ABS(IFNULL(z_score, 0)) DESC, bill_month DESC;