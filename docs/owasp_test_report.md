# OWASP Rules Effectiveness Test Report

Generated on: 2025-09-14 07:29:50

## Executive Summary

This report evaluates the effectiveness of the security scanner against OWASP Top 10 vulnerabilities using CakePHP 3 test cases.

## Test Methodology

- **Framework**: CakePHP 3.x
- **Test Cases**: 10 total files
- **Rules Tested**: 5 OWASP rules
- **Test Structure**: Clean vs Vulnerable files

## Results Summary


### Overall Performance

- **Total Tests**: 10
- **True Positives**: 2
- **False Positives**: 0
- **False Negatives**: 3
- **F1-Score**: 0.571 (57.1%)
- **Precision**: 1.000 (100.0%)
- **Recall**: 0.400 (40.0%)

## Detailed Results by Rule


### OWASP-A02-001

- **Total Tests**: 2
- **True Positives**: 1
- **False Positives**: 0
- **False Negatives**: 0
- **Precision**: 1.000
- **Recall**: 1.000
- **F1-Score**: 1.000
- **Average Detection Time**: 1.516312ms


### OWASP-A03-003

- **Total Tests**: 2
- **True Positives**: 1
- **False Positives**: 0
- **False Negatives**: 0
- **Precision**: 1.000
- **Recall**: 1.000
- **F1-Score**: 1.000
- **Average Detection Time**: 4.346979ms


### OWASP-A03-001

- **Total Tests**: 2
- **True Positives**: 0
- **False Positives**: 0
- **False Negatives**: 1
- **Precision**: 0.000
- **Recall**: 0.000
- **F1-Score**: 0.000
- **Average Detection Time**: 625.979µs


### OWASP-A03-002

- **Total Tests**: 2
- **True Positives**: 0
- **False Positives**: 0
- **False Negatives**: 1
- **Precision**: 0.000
- **Recall**: 0.000
- **F1-Score**: 0.000
- **Average Detection Time**: 638.125µs


### OWASP-A01-001

- **Total Tests**: 2
- **True Positives**: 0
- **False Positives**: 0
- **False Negatives**: 1
- **Precision**: 0.000
- **Recall**: 0.000
- **F1-Score**: 0.000
- **Average Detection Time**: 655.645µs


## Recommendations

### High Priority
- Focus on reducing false negatives for critical vulnerabilities
- Improve pattern matching for complex injection scenarios

### Medium Priority
- Optimize detection performance for large codebases
- Enhance false positive filtering

### Low Priority
- Add support for more PHP frameworks
- Improve detection for edge cases

## Conclusion

The security scanner demonstrates 57.1% effectiveness in detecting OWASP vulnerabilities in CakePHP 3 applications. 
