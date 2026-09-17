| Metric | Estimate | 95% interval | Method |
|---|---:|---|---|
| Accuracy | 1.0000 | [0.9697, 1.0000] | exact Clopper-Pearson |
| Precision | 1.0000 | [0.9598, 1.0000] | exact Clopper-Pearson |
| Recall | 1.0000 | [0.9598, 1.0000] | exact Clopper-Pearson |
| Specificity | 1.0000 | [0.8843, 1.0000] | exact Clopper-Pearson |
| F1 | 1.0000 | [1.0000, 1.0000] | stratified bootstrap; 10000 resamples; seed 20260728 |
| False Acceptance Rate | 0.0000 | [0.0000, 0.0402] | exact Clopper-Pearson |
| False Rejection Rate | 0.0000 | [0.0000, 0.1157] | exact Clopper-Pearson |

The F1 bootstrap interval degenerates at 1.0 when every stratified resample remains perfectly classified; exact class-specific intervals therefore provide a more informative characterization of finite-sample uncertainty.
