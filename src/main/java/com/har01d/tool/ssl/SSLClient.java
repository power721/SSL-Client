package com.har01d.tool.ssl;

import com.har01d.tool.jarg.JCommand;
import com.har01d.tool.jarg.JOption;
import com.har01d.tool.jarg.Jarg;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SSLClient {

    private String host;
    private Integer port;
    private String protocol = "TLS";
    private String data;
    private List<String> ciphers;

    private boolean quiet;
    private boolean debug;
    private boolean verbose;
    private boolean acceptAll;
    private boolean acceptSelfSign;
    private boolean printCert;

    public SSLClient(Jarg jarg) {
        JCommand connect = jarg.getCommand();
        quiet = jarg.isPresent("quiet");
        debug = !quiet && jarg.isPresent("debug");
        verbose = !quiet && jarg.isPresent("verbose");

        acceptSelfSign = connect.isPresent("self");
        acceptAll = connect.isPresent("all");
        printCert = connect.isPresent("print-cert");
        if (connect.isPresent("data")) {
            data = connect.getValue("data");
        }
        if (connect.isPresent("ciphers")) {
            ciphers = connect.getStringValues("ciphers");
        }
        if (connect.isPresent("sslv2")) {
            protocol = "SSLv2";
        } else if (connect.isPresent("sslv3")) {
            protocol = "SSLv3";
        } else if (connect.isPresent("tlsv1")) {
            protocol = "TLS";
        } else if (connect.isPresent("tlsv1.0")) {
            protocol = "TLSv1";
        } else if (connect.isPresent("tlsv1.1")) {
            protocol = "TLSv1.1";
        } else if (connect.isPresent("tlsv1.2")) {
            protocol = "TLSv1.2";
        }

        if (connect.isPresent("keystore")) {
            System.setProperty("javax.net.ssl.keyStore", connect.getValue("keystore"));
            if (connect.isPresent("keystore-password")) {
                System.setProperty("javax.net.ssl.keyStorePassword", connect.getValue("keystore-password"));
            }
            if (connect.isPresent("keystore-type")) {
                System.setProperty("javax.net.ssl.keyStoreType", connect.getValue("keystore-type"));
            }
        }

        if (connect.isPresent("truststore")) {
            System.setProperty("javax.net.ssl.trustStore", connect.getValue("truststore"));
            if (connect.isPresent("truststore-password")) {
                System.setProperty("javax.net.ssl.trustStorePassword", connect.getValue("truststore-password"));
            }
            if (connect.isPresent("truststore-type")) {
                System.setProperty("javax.net.ssl.trustStoreType", connect.getValue("truststore-type"));
            }
        }

        host = jarg.getArgument("host");
        port = Integer.parseInt(jarg.getArgument("port"));
    }

    public static void main(String[] args) throws IOException {
        Jarg jarg = new Jarg("ssl-client", "Java SSL client");
        jarg.addSection(Jarg.AUTHOR, "Harold Li");
        jarg.autoHelp();
        jarg.addOption("--debug|-d", "Show debug message", false);
        jarg.addOption("--verbose|-v", "Show verbose message", false);
        jarg.addOption("--quiet|-q", "No output", false);
        jarg.addCommand("help", "Show the help text");
        jarg.addCommand("version", "Show the version");
        jarg.addCommand("info", "Show the Java info");
        List<JOption> options = new ArrayList<>();
        JCommand connect = jarg.addCommand("connect", "Connect to a SSL server");
        connect.addOption("-s|--self", "Accept self sign certificate", false);
        connect.addOption("-a|--all", "Accept all certificate", false);
        connect.addOption("--print-cert", "Print the server certificate", false);
        connect.addOption("--ciphers", "A comma-separated list of SSL/TLS ciphers");
        connect.addOption("--keystore|-k", "The keystore file");
        connect.addOption("--keystore-type", "The keystore type");
        connect.addOption("--keystore-password", "The keystore password");
        connect.addOption("--truststore|-t", "The truststore file");
        connect.addOption("--truststore-type", "The truststore type");
        connect.addOption("--truststore-password", "The truststore password");
        options.add(connect.addOption("-2|--sslv2", "Use SSLv2", false));
        options.add(connect.addOption("-3|--sslv3", "Use SSLv3", false));
        options.add(connect.addOption("-1|--tlsv1", "Use => TLSv1 (Default)", false));
        options.add(connect.addOption("--tlsv1.0", "Use TLSv1.0", false));
        options.add(connect.addOption("--tlsv1.1", "Use TLSv1.1", false));
        options.add(connect.addOption("--tlsv1.2", "Use TLSv1.2", false));
        connect.addOption("--data|-d", "Send data to server");
        connect.addParameter("host").required();
        connect.addParameter("port").required();
        jarg.addCommand("ciphers", "Show the supported cipher suites").addOptions(options);
        jarg.cloneCommand("connect", "test-ciphers", "Test which ciphers work");

        JCommand command = null;
        try {
            jarg.parse(args);
            command = jarg.requireCommand();
        } catch (Exception e) {
            jarg.handleError(e);
        }

        switch (command.getName()) {
            case "version":
                System.out.println("1.0");
                break;
            case "info":
                printJavaInfo();
                break;
            case "ciphers":
                new SSLClient(jarg).listCiphers();
                break;
            case "test-ciphers":
                new SSLClient(jarg).testCiphers();
                break;
            case "connect":
                new SSLClient(jarg).connect();
                break;
            default:
                jarg.printHelp(System.out);
        }
    }

    private static void printJavaInfo() {
        System.out.println("Java: " + System.getProperty("java.version"));
        System.out.println("Java Runtime: " + System.getProperty("java.runtime.version"));
        System.out.println("Java Home: " + System.getProperty("java.home"));
    }

    private void listCiphers() throws IOException {
        SSLContext context = getDefaultSSLContext();
        SSLSocketFactory factory = context.getSocketFactory();
        String[] cipherSuites = factory.getSupportedCipherSuites();
        List<String> ciphers = Arrays.asList(factory.getDefaultCipherSuites());
        System.out.println(cipherSuites.length + " supported cipher suites(" + ciphers.size() + " enabled):");
        for (String cipher : cipherSuites) {
            System.out.println(cipher + (ciphers.contains(cipher) ? " *" : ""));
        }
    }

    private void connect() throws IOException {
        if (verbose) {
            System.setProperty("javax.net.debug", "all");
        } else if (debug) {
            System.setProperty("javax.net.debug", "ssl");
        }

        SSLSocketFactory factory = getSslSocketFactory();

        if (verbose) {
            try {
                InetAddress[] addresses = InetAddress.getAllByName(host);
                for (InetAddress address : addresses) {
                    System.out.println(address);
                }
            } catch (Exception e) {
                // ignore
            }
        }

        if (!quiet) {
            System.out.println("Connecting... to " + host + ":" + port);
        }

        try (SSLSocket sslSocket = (SSLSocket) factory.createSocket(host, port);
             OutputStream os = sslSocket.getOutputStream();
             BufferedReader in = new BufferedReader(new InputStreamReader(
                     sslSocket.getInputStream()))) {

            if (ciphers != null) {
                if (!quiet) {
                    System.out.println("Enabled cipher suites: " + ciphers);
                }
                sslSocket.setEnabledCipherSuites(ciphers.toArray(new String[0]));
            }

            sslSocket.startHandshake();
            if (!quiet) {
                System.out.println("Connected to " + host + ":" + port);
                SSLSession sslSession = sslSocket.getSession();
                System.out.println("Protocol: " + sslSession.getProtocol());
                System.out.println("CipherSuit: " + sslSession.getCipherSuite());

                if (printCert) {
                    System.out.println("PeerCertificates:");
                    printCertificates(sslSession.getPeerCertificates());
                }
            }

            if (data != null) {
                os.write(data.getBytes(StandardCharsets.UTF_8));
            }

            String line;
            if (!quiet) {
                System.out.println("Response:");
                while ((line = in.readLine()) != null) {
                    System.out.println(line);
                }
            }
        }
    }

    private SSLSocketFactory getSslSocketFactory() throws IOException {
        SSLSocketFactory factory;
        SSLContext context;
        if (acceptAll) {
            context = getNoopSSLContext();
        } else if (acceptSelfSign) {
            context = getEasySSLContext();
        } else {
            context = getDefaultSSLContext();
        }
        factory = context.getSocketFactory();
        return factory;
    }

    private void testCiphers() throws IOException {
        if (debug) {
            System.setProperty("javax.net.debug", "ssl");
        }

        if (!quiet) {
            System.out.println("Connecting... to " + host + ":" + port);
        }

        SSLSocketFactory factory = getSslSocketFactory();
        for (String cipher : factory.getSupportedCipherSuites()) {
            if (testCipherSuite(factory, cipher)) {
                System.out.println(cipher);
            }
        }
    }

    private boolean testCipherSuite(SSLSocketFactory factory, String cipher) throws IOException {
        try (SSLSocket sslSocket = (SSLSocket) factory.createSocket(host, port)) {
            sslSocket.setEnabledCipherSuites(new String[]{cipher});
            sslSocket.startHandshake();
        } catch (SSLHandshakeException e) {
            if (e.getCause() instanceof sun.security.validator.ValidatorException) {
                throw e;
            } else {
                return false;
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    private void printCertificates(Certificate[] certificates) {
        for (Certificate certificate : certificates) {
            System.out.println(certificate.toString());
        }
    }

    private SSLContext getDefaultSSLContext() throws IOException {
        try {
            SSLContext context = SSLContext.getInstance(protocol);
            context.init(null, null, null);
            return context;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private SSLContext getEasySSLContext() throws IOException {
        try {
            SSLContext context = SSLContext.getInstance(protocol);
            context.init(null, new TrustManager[]{new AcceptSelfSignedTrustManager(null)}, null);
            return context;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private SSLContext getNoopSSLContext() throws IOException {
        try {
            SSLContext context = SSLContext.getInstance(protocol);
            context.init(null, new TrustManager[]{new NoopTrustManager()}, null);
            return context;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

}
