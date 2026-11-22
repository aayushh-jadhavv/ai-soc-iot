package org.raspigateway.demo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;

final class DemoClient {
    private DemoClient() {}

    static byte[] readBody(InputStream input) throws IOException {
        try (input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > 65536) throw new IOException("Report response is too large.");
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    static String reports(String address) throws IOException {
        URI base;
        try {
            base = URI.create(address.trim());
        } catch (IllegalArgumentException error) {
            throw new IOException("Enter a Pi address such as http://192.168.1.50:8080.");
        }
        if (!"http".equals(base.getScheme()) || base.getHost() == null
                || base.getPort() < 1 || base.getPort() > 65535
                || base.getUserInfo() != null || base.getQuery() != null
                || base.getFragment() != null
                || !(base.getPath().isEmpty() || base.getPath().equals("/"))) {
            throw new IOException("Enter the Pi's HTTP address and port without a report path.");
        }
        String live = getReports(base, "/v1/reports", true);
        return live == null ? getReports(base, "/demo/reports", false) : live;
    }

    private static String getReports(URI base, String route, boolean allowMissing) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) base.resolve(route)
                .toURL().openConnection();
        connection.setConnectTimeout(4000);
        connection.setReadTimeout(4000);
        connection.setInstanceFollowRedirects(false);
        connection.setUseCaches(false);
        try {
            int status = connection.getResponseCode();
            if (status == 404 && allowMissing) return null;
            if (status != 200) throw new IOException("Pi returned HTTP " + status + ".");
            return new String(readBody(connection.getInputStream()), StandardCharsets.UTF_8);
        } finally {
            connection.disconnect();
        }
    }
}
