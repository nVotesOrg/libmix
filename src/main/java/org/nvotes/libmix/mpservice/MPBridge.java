package org.nvotes.libmix.mpservice;

import java.util.LinkedList;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;
import java.math.BigInteger;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.squareup.jnagmp.Gmp;
import org.nvotes.libmix.Util;

/**
 *  Bridges modpow calls into a faster implementation, provided by MPService.
 *
 *  The bridge is implemented with a per-thread record/replay mechanism
 *  that captures modpow calls inside a closure scope. The requests
 *  are then passed to MPService. The results are passed back into
 *  the closure on a second replay run.
 */
public class MPBridge {
    private final static Logger logger = LoggerFactory.getLogger(MPBridge.class);

    private static boolean useGmp = Util.getEnvBoolean("libmix.gmp");
    private static boolean useExtractor = Util.getEnvBoolean("libmix.extractor");

    private BigInteger dummy = new BigInteger("2");
    private BigInteger modulus = null;

    private boolean recording = false;
    private boolean replaying = false;

    private ArrayList<ModPow2> requests = new ArrayList<ModPow2>();
    private LinkedList<BigInteger> answers = null;

    /**
     *  Allows extraction from multithreaded code, creating one
     *  MPBridge object per thread.
     */
    private static ThreadLocal<MPBridge> instance = new ThreadLocal<MPBridge>() {
        @Override protected MPBridge initialValue() {
            return new MPBridge();
        }
    };

    /**
     *  Returns the MPBridge instance associated with the calling thread.
     */
    public static MPBridge i() {
        return instance.get();
    }

    /**
     *  Starts the recording phase.
     *
     *  The passed in value will be returned as the dummy result of
     *  modpow calls during the record phase.
     */
    public static void startRecord(String value) {
        i().dummy = new BigInteger(value);
        if(i().requests.size() != 0)    throw new IllegalStateException();
        i().recording = useExtractor;
        i().modulus = null;
    }

    /**
     *  Starts the recording phase.
     *
     *  Modpow calls will be returned the default dummy value of 2.
     */
    public static void startRecord() {
        startRecord("2");
    }

    /**
     *  Stops the recording, returning all collected modpows.
     */
    public static ModPow2[] stopRecord() {
        i().recording = false;

        return i().requests.toArray(new ModPow2[0]);
    }

    /**
     *  Starts the replaying phase.
     *
     *  Modpow requests will be given results computed
     *  by MPService.
     */
    public static void startReplay(BigInteger[] answers_) {
        if(answers_.length != i().requests.size()) throw new IllegalArgumentException(answers_.length + "!=" + i().requests.size());
        i().answers = new LinkedList<BigInteger>(Arrays.asList(answers_));

        i().replaying = true;
    }

    /**
     *  Stops the replaying phase.
     */
    public static void stopReplay() {
        if(i().answers.size() != 0) throw new IllegalStateException();

        i().replaying = false;
    }

    /**
     *  Resets this MPBridge instance.
     */
    public static void reset() {
        i().requests.clear();
    }

    /**
     *  Adds a modpow request to the list to be computed by MPService.
     */
    public static void addModPow(BigInteger base, BigInteger pow, BigInteger mod) {
        MPBridge i = i();
        if(!i.recording) throw new IllegalStateException();
        if(i.modulus == null) {
            i.modulus = mod;
        }
        // sanity check
        else if(!i.modulus.equals(mod)) {
            throw new RuntimeException(i.modulus + "!=" + mod);
        }

        i.requests.add(new ModPow2(base, pow));
    }

    /**
     *  Returns a result, as calculated by MPService.
     */
    public static BigInteger getModPow() {
        if(i().recording) throw new IllegalStateException();

        return i().answers.removeFirst();
    }

    /**
     *  Extracts modpows from given closure, executes them via MPService
     *
     *  The closure is first executed in record mode, where modpow requests are saved.
     *  The requests are computed by MPService.
     *  The closure is then executed in replay mode, returning the computed values.
     */
    public static <T> T run(Supplier<T> f, String v) {
        a();
        startRecord(v);
        long now = System.currentTimeMillis();
        T ret = f.get();
        long r = System.currentTimeMillis() - now;
        logger.trace("Record: [" + r + " ms]");
        ModPow2[] reqs = stopRecord();
        b(3);
        if(reqs.length > 0) {
            long now2 = System.currentTimeMillis();
            BigInteger[] answers = MPService.compute(reqs, i().modulus);
            long c = System.currentTimeMillis() - now2;
            startReplay(answers);
            ret = f.get();
            long t = System.currentTimeMillis() - now;
            logger.trace("Compute: [" + c + " ms] R+C: [" + (r+c) + " ms] Total: [" + t + " ms]");
            stopReplay();
        }
        reset();

        return ret;
    }

    /**
     *  Extracts modpow calls from the given closure.
     *
     *  Uses the default dummy value of 2
     */
    public static <T> T run(Supplier<T> f) {
        return run(f, "2");
    }

    /**
     *  Method to intercept modpow calls.
     *
     *  For extraction to work, the target code must call this version
     *  of modpow. If recording is activated, adds the request and returns
     *  the dummy value. If replaying, returns the result computed by
     *  MPService.
     */
    public static BigInteger modPow(BigInteger base, BigInteger pow, BigInteger mod) {
        MPBridge i = i();
        if(i.recording) {
            total++;
            addModPow(base, pow, mod);
            return i.dummy;
        }
        else if(i.replaying) {
            return getModPow();
        }
        else if(i.replayingDebug) {
            ModPowResult result = getModPowDebug();
            boolean ok = base.equals(result.base()) && pow.equals(result.pow()) && mod.equals(result.mod());
            if(!ok) throw new RuntimeException();

            return result.result();
        }
        else {
            total++;
            if(useGmp) {
                return Gmp.modPowInsecure(base, pow, mod);
            }
            else {
                return base.modPow(pow, mod);
            }
        }
    }

    /**
     *  Returns the modulus common to all modpow requests.
     *
     */
    public static BigInteger getModulus() {
        return i().modulus;
    }

    /****************************** DEBUG STUFF ****************************/

    private boolean replayingDebug = false;
    private List<ModPowResult> answersDebug = null;

    // tracing vars
    public long before = 0;
    public static long total = 0;
    private long beforeTime = 0;

    public static void startReplayDebug(ModPowResult[] answers_) {
        if(answers_.length != i().requests.size()) throw new IllegalArgumentException(answers_.length + "!=" + i().requests.size());
        i().answersDebug = new LinkedList<ModPowResult>(Arrays.asList(answers_));

        i().replayingDebug = true;
    }

    public static void stopReplayDebug() {
        if(i().answersDebug.size() != 0) throw new IllegalStateException();

        i().replayingDebug = false;
    }

    public static ModPowResult getModPowDebug() {
        if(i().recording) throw new IllegalStateException();

        return i().answersDebug.remove(0);
    }

    public static <T> T parDebug(Supplier<T> f, String v) {
        a();
        startRecord(v);
        long now = System.currentTimeMillis();
        T ret = f.get();
        long r = System.currentTimeMillis() - now;
        logger.trace("R: [" + r + " ms]");
        ModPow2[] reqs = stopRecord();
        b(3);
        if(reqs.length > 0) {
            long now2 = System.currentTimeMillis();

            ModPowResult[] answers = MPService.computeDebug(reqs, i().modulus);
            long c = System.currentTimeMillis() - now2;

            startReplayDebug(answers);
            ret = f.get();
            long t = System.currentTimeMillis() - now;
            logger.trace("\nC: [" + c + " ms] T: [" + t + " ms] R+C: [" + (r+c) + " ms]");

            stopReplayDebug();
        }
        reset();

        return ret;
    }

    public static <T> T parDebug(Supplier<T> f) {
        return parDebug(f, "2");
    }

    public static void a() {
        i().beforeTime = System.currentTimeMillis();
    }

    public static void b(int trace) {
        MPBridge i = i();
        StackTraceElement[] traces = Thread.currentThread().getStackTrace();
        StackTraceElement caller = traces[trace];
        long diffTime = System.currentTimeMillis() - i.beforeTime;
        logger.trace(">>> " + caller.getFileName() + ":" + caller.getLineNumber() + " [" + diffTime + " ms]" + " (" + total + ")");
    }
}