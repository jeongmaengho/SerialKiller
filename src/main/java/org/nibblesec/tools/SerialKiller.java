/*
 * SerialKiller.java
 *
 * Copyright (c) 2015-2016 Luca Carettoni
 *
 * SerialKiller is an easy-to-use look-ahead Java deserialization library
 * to secure application from untrusted input. When Java serialization is
 * used to exchange information between a client and a server, attackers
 * can replace the legitimate serialized stream with malicious data.
 * SerialKiller inspects Java classes during naming resolution and allows
 * a combination of blacklisting/whitelisting to secure your application.
 *
 * Dual-Licensed Software: Apache v2.0 and GPL v2.0
 */
// Modified by Bizflow Corp., 2025-11-09
package org.nibblesec.tools;

import org.apache.commons.configuration2.XMLConfiguration;
import org.apache.commons.configuration2.builder.ReloadingFileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.configuration2.reloading.PeriodicReloadingTrigger;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.*;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static java.util.Objects.requireNonNull;

public class SerialKiller extends ObjectInputStream {

    private static final Log LOGGER = LogFactory.getLog(SerialKiller.class.getName());

    private static final Map<String, Configuration> configs = new ConcurrentHashMap<>();

    private final Configuration config;
    private final boolean profiling;

    /**
     * SerialKiller constructor, returns instance of ObjectInputStream.
     *
     * @param inputStream The original InputStream, used by your service to receive serialized objects
     * @param configFile The location of the config file (absolute path)
     * @throws java.io.IOException File I/O exception
     * @throws IllegalStateException Invalid configuration exception
     */
    public SerialKiller(final InputStream inputStream, final String configFile) throws IOException {
        super(inputStream);

        config = configs.computeIfAbsent(configFile, Configuration::new);
        profiling = config.isProfiling();
    }

    @Override
    protected Class<?> resolveClass(final ObjectStreamClass serialInput) throws IOException, ClassNotFoundException {
        try {
            config.reloadIfNeeded();
        } catch (ConfigurationException e) {
            throw new RuntimeException(e);
        }

        // Enforce SerialKiller's blacklist
        for (Pattern blackPattern : config.blacklist()) {
            Matcher blackMatcher = blackPattern.matcher(serialInput.getName());

            if (blackMatcher.find()) {
                if (profiling) {
                    // Reporting mode
                    LOGGER.info(String.format("Blacklist match: '%s'", serialInput.getName()));
                } else {
                    // Blocking mode
                    LOGGER.error(String.format("Blocked by blacklist '%s'. Match found for '%s'", new Object[] {blackPattern.pattern(), serialInput.getName()}));
                    throw new InvalidClassException(serialInput.getName(), "Class blocked from deserialization (blacklist)");
                }
            }
        }

        // Enforce SerialKiller's whitelist
        boolean safeClass = false;

        for (Pattern whitePattern : config.whitelist()) {
            Matcher whiteMatcher = whitePattern.matcher(serialInput.getName());

            if (whiteMatcher.find()) {
                safeClass = true;

                if (profiling) {
                    // Reporting mode
                    LOGGER.info(String.format("Whitelist match: '%s'", serialInput.getName()));
                }

                // We have found a whitelist match, no need to continue
                break;
            }
        }

        if (!safeClass && !profiling) {
            // Blocking mode
            LOGGER.error(String.format("Blocked by whitelist. No match found for '%s'", serialInput.getName()));
            throw new InvalidClassException(serialInput.getName(), "Class blocked from deserialization (non-whitelist)");
        }

        return super.resolveClass(serialInput);
    }

    static final class Configuration {
        private ReloadingFileBasedConfigurationBuilder<XMLConfiguration> builder;
        private XMLConfiguration config;

        private PatternList blacklist;
        private PatternList whitelist;
        private File configFile;

        Configuration(final String configPath) {
            try {
                if (null == configPath) {
                    throw new ConfigurationException("configPath is null");
                }
                configFile = new File(configPath);
                if (configFile.length() == 0 || !configFile.exists() || !configFile.canRead()) {
                    throw new ConfigurationException("configPath is invalid: " + configPath);
                }

                Parameters params = new Parameters();
                builder =
                        new ReloadingFileBasedConfigurationBuilder<>(XMLConfiguration.class)
                                .configure(params.xml()
                                        .setFile(configFile)
                                        .setValidating(false)
                                );

                PeriodicReloadingTrigger trigger =
                        new PeriodicReloadingTrigger(builder.getReloadingController(), null, 6, TimeUnit.SECONDS);
                trigger.start();

                config = builder.getConfiguration();
                init(config);

            } catch (ConfigurationException | PatternSyntaxException e) {
                throw new IllegalStateException("SerialKiller not properly configured: " + e.getMessage(), e);
            }
        }

        private void init(final XMLConfiguration config) {
            blacklist = new PatternList(config.getStringArray("blacklist.regexps.regexp"));
            whitelist = new PatternList(config.getStringArray("whitelist.regexps.regexp"));
        }

        void reloadIfNeeded() throws ConfigurationException, IOException {
            if (null != builder) {
                builder.getReloadingController().checkForReloading(null);
                config = builder.getConfiguration();
                init(config);
            }
        }

        Iterable<Pattern> blacklist() {
            return blacklist;
        }

        Iterable<Pattern> whitelist() {
            return whitelist;
        }

        boolean isProfiling() {
            if (null == config) {
                return false;
            }
            return config.getBoolean("mode.profiling", false);
        }
    }

    static final class PatternList implements Iterable<Pattern> {
        private final Pattern[] patterns;

        PatternList(final String... regExps) {

            requireNonNull(regExps, "regExps");

            this.patterns = new Pattern[regExps.length];
            for (int i = 0; i < regExps.length; i++) {
                patterns[i] = Pattern.compile(regExps[i]);
            }
        }

        @Override
        public Iterator<Pattern> iterator() {
            return new Iterator<Pattern>() {
                int index = 0;

                @Override
                public boolean hasNext() {
                    return index < patterns.length;
                }

                @Override
                public Pattern next() {
                    return patterns[index++];
                }

                @Override
                public void remove() {
                    throw new UnsupportedOperationException("remove");
                }
            };
        }

        @Override
        public String toString() {
            return Arrays.toString(patterns);
        }

    }
}