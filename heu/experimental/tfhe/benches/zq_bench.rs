// Copyright 2022 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate colored;
extern crate criterion;
extern crate log;
extern crate simple_logger;
extern crate torus;

use std::borrow::BorrowMut;

use colored::Colorize;
use criterion::{Criterion, SamplingMode};
use simple_logger::SimpleLogger;

use torus::measure_duration;
use torus::zq::decryptor::Decryptor;
use torus::zq::encryptor::Encryptor;
use torus::zq::evaluator::Evaluator;
use torus::zq::key_generator::KeyGenerator;
use torus::zq::Ciphertext;

// Rust 的 benchmark 都不好用
// 自带的 bencher 不支持 release 编译
// criterion 跑的巨慢无比，每个 bench 的 iteration 最少10次，不支持跑1次
const TEST_SIZE: usize = 1000;

fn bench_add(bencher: &mut Criterion) {
    SimpleLogger::new().with_colors(true).init().unwrap();
    let mut bencher_group = bencher.benchmark_group("aa");
    bencher_group.sampling_mode(SamplingMode::Flat).sample_size(10);

    // create an encoder
    let kg = KeyGenerator::new(concrete::RLWE128_2048_1, concrete::LWE128_2048, 5, 3);
    measure_duration!("Generate sk", {
        let sk = kg.generate_only_sk();
    });

    let encryptor = Encryptor::new(&sk).unwrap();
    let decryptor = Decryptor::new(&sk);
    let evaluator = Evaluator::new_levelled_evaluator();

    let mut res = encryptor.encrypt(0).unwrap();
    let mut cts: Vec<Ciphertext> = Vec::new();

    measure_duration!("Encrypt", {
        for i in 0usize..TEST_SIZE {
            cts.push(encryptor.encrypt(i as u32).unwrap());
        }
    });

    // bench add
    bencher_group.bench_function("Sum", |b| {
        for i in 0..TEST_SIZE {
            b.iter(|| {
                evaluator.add_inplace(&mut res, &(cts[i])).unwrap();
            })
        }
    });

    println!("Sum is {}", decryptor.decrypt(&res).unwrap())
}

criterion::criterion_group!(benches, bench_add);
criterion::criterion_main!(benches);
