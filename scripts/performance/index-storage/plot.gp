#!/usr/bin/gnuplot
#
# Copyright 2024 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set term png
set output "graph.png"

set style line 1 lc rgb "#40a7db"
set style line 2 lc rgb "#b38df0"
set yrange [0:]
set style fill solid
set boxwidth 0.5
set ylabel "Latency (nanoseconds)"
set xlabel "Operation\nAverage over (N operations),\nsearches across " . entries . " entries"
set format y '%.0f'
set bmargin 6
set grid y
set tics font "sans,10"

plot "results.dat" every ::0::1 using 1:3:xtic(2) with boxes linestyle 1 notitle, \
    "results.dat" every ::0::1 using 1:($3+1000000):(sprintf('%3.2f', $3)) with labels font "sans,10" notitle, \
    "results.dat" every ::2::3 using 1:3:xtic(2) with boxes linestyle 2 notitle, \
    "results.dat" every ::2::3 using 1:($3+1000000):(sprintf('%3.2f', $3)) with labels font "sans,10" notitle
