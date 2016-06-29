/*
 * Copyright (c) 2016, Alun Evans.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  * Neither the name of Oracle nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

package net.badgerous;

import com.google.common.hash.Hashing;
import fr.cryptohash.JCAProvider;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.apache.commons.math3.distribution.ZipfDistribution;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OperationsPerInvocation;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

/**
 * Hashing Benchmarks.
 * @author Alun Evans (alun@badgerous.net)
 * @version 1.0
 */
@Warmup(
    iterations = 3,
    time = 5,
    timeUnit = TimeUnit.SECONDS)
@Measurement(
    iterations = 10,
    time = 5,
    timeUnit = TimeUnit.SECONDS)
@Fork(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Benchmark)
public class HashingBenchmark {
    /**
     * Distribution Size.
     */
    private static final int DIST_SIZE = 100_000;

    /**
     * Maximal length.
     */
    private static final int MAX_LENGTH = 1_000;

    /**
     * Zipfian generator for lengths.
     */
    private static final ZipfDistribution ZIPFN =
        new ZipfDistribution(HashingBenchmark.MAX_LENGTH, 1.0);

    /**
     * RNG.
     */
    private static final Random RANDOM = new Random();


    @Benchmark
    @OperationsPerInvocation(HashingBenchmark.DIST_SIZE)
    public void testMD5(
        final HashingBenchmark.Messages messages, final Blackhole black
    ) {
        for (int idx=0; idx<HashingBenchmark.DIST_SIZE; ++idx) {
            messages.MD5.reset();
            messages.MD5.update(messages.messages[idx]);
            messages.MD5.digest(messages.digest);
            black.consume(messages.digest);
        }
    }

    @Benchmark
    @OperationsPerInvocation(HashingBenchmark.DIST_SIZE)
    public void testMD5_bc(
        final HashingBenchmark.Messages messages, final Blackhole black
    ) {
        for (int idx=0; idx<HashingBenchmark.DIST_SIZE; ++idx) {
            messages.MD5_bc.reset();
            messages.MD5_bc.update(messages.messages[idx]);
            messages.MD5_bc.digest(messages.digest);
            black.consume(messages.digest);
        }
    }

    @Benchmark
    @OperationsPerInvocation(HashingBenchmark.DIST_SIZE)
    public void testMD5_sap(
        final HashingBenchmark.Messages messages, final Blackhole black
    ) {
        for (int idx=0; idx<HashingBenchmark.DIST_SIZE; ++idx) {
            messages.MD5_sap.reset();
            messages.MD5_sap.update(messages.messages[idx]);
            messages.MD5_sap.digest(messages.digest);
            black.consume(messages.digest);
        }
    }

    @Benchmark
    @OperationsPerInvocation(HashingBenchmark.DIST_SIZE)
    public void testMD5_google(
        final HashingBenchmark.Messages messages, final Blackhole black
    ) {
        for (int idx=0; idx<HashingBenchmark.DIST_SIZE; ++idx) {
            Hashing
                .md5()
                .hashBytes(messages.messages[idx])
                .writeBytesTo(messages.digest, 0, messages.digest.length);
            black.consume(messages.digest);
        }
    }
    @State(Scope.Thread)
    public static class Messages {

        public final Provider saphir;
        public final Provider bouncy;
        public final MessageDigest MD5;
        public final MessageDigest MD5_bc;
        public final MessageDigest MD5_sap;
        public final byte[] digest;

        public final byte[][] messages = new byte[HashingBenchmark.DIST_SIZE][];

        public Messages() {
            try {
                this.saphir = new JCAProvider();
                Security.addProvider(this.saphir);
                this.bouncy = new BouncyCastleProvider();
                Security.addProvider(this.bouncy);
                this.MD5 = MessageDigest.getInstance("MD5");
                this.MD5_bc = MessageDigest.getInstance("MD5", this.bouncy);
                this.MD5_sap = MessageDigest.getInstance("MD5", this.saphir);
                this.digest = new byte[this.MD5.getDigestLength()];
            } catch (final NoSuchAlgorithmException ex) {
                throw new IllegalStateException(ex);
            }
        }

        @Setup(Level.Trial)
        public void setup() {
            for (int idx=0; idx < HashingBenchmark.DIST_SIZE; ++idx) {
                this.messages[idx] = new byte[HashingBenchmark.ZIPFN.sample()];
                HashingBenchmark.RANDOM.nextBytes(this.messages[idx]);
            }
        }

    }

}
