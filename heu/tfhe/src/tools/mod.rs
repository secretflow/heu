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

// This macro allows to compute the duration of the execution of the expressions enclosed. Note that
// the variables are not captured.
#[macro_export]
macro_rules! measure_duration {
    ($title: tt, {$($block:tt)+}) => {
        println!("{} ... ", $title);
        let __now = std::time::SystemTime::now();
        $(
           $block
        )+
        let __time = __now.elapsed().unwrap().as_millis() as f64 / 1000.;
        let __s_time = format!("{} s", __time);
        println!("{} ... Duration: {}", $title, __s_time.green().bold());
    }
}
