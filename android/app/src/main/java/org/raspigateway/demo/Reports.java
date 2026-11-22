package org.raspigateway.demo;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class Reports {
    static final class Report {
        final String id, device, summary, coverage, recommendation, action;
        final int revision;
        final Double score;
        final boolean live;
        final String detectorDetails;

        Report(JSONObject object, boolean live) throws JSONException {
            this.live = live;
            id = requiredText(object, "report_id");
            device = requiredText(object, "device");
            summary = requiredText(object, "factual_summary");
            coverage = requiredText(object, "coverage");
            recommendation = requiredText(object, "recommendation");
            action = requiredText(object, "action_status");
            revision = positiveInteger(object, "revision");
            Object rawScore = object.get("score");
            if (rawScore == JSONObject.NULL) {
                score = null;
            } else if (rawScore instanceof Number) {
                double value = ((Number) rawScore).doubleValue();
                if (!(value >= 0 && value <= 1)) throw new JSONException("Invalid detector score.");
                score = value;
            } else {
                throw new JSONException("Invalid detector score.");
            }
            if (live) {
                String status = requiredText(object, "detector_status");
                String model = requiredText(object, "model_id");
                if (!("ok".equals(status) && score != null
                        || ("abstain".equals(status) || "error".equals(status)) && score == null)
                        || !"uncalibrated_sigmoid".equals(requiredText(object, "score_type"))
                        || !"NOT_EXECUTED".equals(action)) {
                    throw new JSONException("Inconsistent live detector result.");
                }
                String error = score == null ? " (" + requiredText(object, "error_code") + ")" : "";
                long start = timestamp(object, "window_start_ms");
                long end = timestamp(object, "window_end_ms");
                if (end - start != 8000) throw new JSONException("Invalid observation window.");
                detectorDetails = "\n\nIDS: " + status + error + " · " + model
                        + "\nObserved (UTC): " + Instant.ofEpochMilli(start) + " to " + Instant.ofEpochMilli(end)
                        + "\nObserve only · Score is uncalibrated";
            } else {
                detectorDetails = "";
            }
        }

        String actionLabel() {
            switch (action) {
                case "NOT_EXECUTED": return "Not executed";
                case "INSTALLED": return "Restriction installed";
                case "FAILED": return "Restriction failed";
                default: return "Unknown status (" + action + ")";
            }
        }
    }

    final String gatewayId;
    final boolean live;
    final List<Report> entries = new ArrayList<>();

    Reports(String json) throws JSONException {
        JSONObject root = new JSONObject(json);
        if (positiveInteger(root, "schema_version") != 1) {
            throw new JSONException("Unsupported report schema.");
        }
        String source = requiredText(root, "data_source");
        live = "live".equals(source);
        if (!live && !"synthetic".equals(source)) throw new JSONException("Unknown report source.");
        gatewayId = requiredText(root, "gateway_id");
        JSONArray reports = root.getJSONArray("reports");
        Set<String> identities = new HashSet<>();
        for (int i = 0; i < reports.length(); i++) {
            Report report = new Report(reports.getJSONObject(i), live);
            if (!identities.add(report.id + ":" + report.revision)) {
                throw new JSONException("Duplicate report revision.");
            }
            entries.add(report);
        }
    }

    private static String requiredText(JSONObject object, String key) throws JSONException {
        Object value = object.get(key);
        if (!(value instanceof String) || ((String) value).trim().isEmpty()) {
            throw new JSONException("Invalid " + key + ".");
        }
        return (String) value;
    }

    private static long timestamp(JSONObject object, String key) throws JSONException {
        Object value = object.get(key);
        if (!(value instanceof Integer || value instanceof Long) || ((Number) value).longValue() < 0) {
            throw new JSONException("Invalid " + key + ".");
        }
        return ((Number) value).longValue();
    }

    private static int positiveInteger(JSONObject object, String key) throws JSONException {
        Object value = object.get(key);
        if (!(value instanceof Integer) || (int) value < 1) {
            throw new JSONException("Invalid " + key + ".");
        }
        return (int) value;
    }
}
