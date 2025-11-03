# Two-Time Pad Cryptanalysis

A Python implementation of the automated cryptanalysis method described in:

**"A Natural Language Approach to Automated Cryptanalysis of Two-time Pads"**  
*Joshua Mason, Kathryn Watkins, Jason Eisner, and Adam Stubblefield*  
ACM Conference on Computer and Communications Security (CCS), 2006

## Overview

This project demonstrates how natural language processing techniques can be used to automatically break two-time pad encryption - a critical vulnerability that occurs when the same keystream is reused to encrypt multiple plaintexts.

### The Problem

When a stream cipher keystream is reused:
```
c₁ = p ⊕ k
c₂ = q ⊕ k
→ c₁ ⊕ c₂ = p ⊕ q
```

The keystream cancels out, leaving only the XOR of the two plaintexts. This implementation uses 7-gram language models and the Viterbi algorithm to recover both original plaintexts.

## Features

- **7-gram character language models** with Witten-Bell smoothing
- **Viterbi algorithm** with beam search for efficient decoding
- **Stream switching detection** to handle ambiguous plaintext assignment
- **95.8% accuracy** on mixed natural language text
- Clean, well-documented code (~300 lines)

## Requirements
```bash
Python 3.7+
```

No external dependencies required - uses only standard library!

## Installation
```bash
git clone https://github.com/yourusername/two-time-pad-cracker.git
cd two-time-pad-cracker
```

## Usage

### Quick Start

Run the built-in test suite:
```bash
python two_time_pad.py
```

This will:
1. Train two language models on sample corpora
2. Run 4 test cases (49 to 525 bytes)
3. Display accuracy and timing results

### Custom Messages
```python
from two_time_pad import LanguageModel, TwoTimePadCracker, create_training_corpus

# Train models
corpus1, corpus2 = create_training_corpus()
model1 = LanguageModel(n=7)
model2 = LanguageModel(n=7)
model1.train(corpus1)
model2.train(corpus2)

# Your messages
plaintext1 = b"Hello, this is a secret message"
plaintext2 = b"Another secret text goes here!!"

# Make same length
min_len = min(len(plaintext1), len(plaintext2))
plaintext1 = plaintext1[:min_len]
plaintext2 = plaintext2[:min_len]

# Create XOR stream
xor_stream = bytes(a ^ b for a, b in zip(plaintext1, plaintext2))

# Crack it!
cracker = TwoTimePadCracker(model1, model2, beam_width=200)
recovered1, recovered2 = cracker.crack(xor_stream)

print(f"Recovered 1: {recovered1}")
print(f"Recovered 2: {recovered2}")
```

## Results

| Test Case | Length | Accuracy | Time |
|-----------|--------|----------|------|
| Short | 49 bytes | 89.8% | 1.44s |
| Medium | 126 bytes | 84.9% | 8.95s |
| Long | 251 bytes | **100.0%** | 28.75s |
| Very Long | 525 bytes | 97.0% | 100.66s |
| **Overall** | **951 bytes** | **95.8%** | **139.8s** |

*Tested on Intel i7-12700KF*

### Comparison

- **Original Paper**: 99% accuracy on HTML documents
- **Our Implementation**: 95.8% accuracy on mixed natural language text
- **Speed**: 147 ms/byte (paper reported ~200 ms/byte on 2006 hardware)

## How It Works

### 1. Language Models

Trains two 7-gram character-level language models using:
- **Witten-Bell smoothing** for unseen n-grams
- **Backoff mechanism** to shorter contexts
- **BOM/EOM markers** for message boundaries

### 2. Viterbi Algorithm

Uses dynamic programming to find the most probable plaintext pair:
- **State space**: `(position, context₁, context₂)`
- **Transitions**: All valid character pairs where `p ⊕ q = x`
- **Scoring**: `P(p|context₁) × P(q|context₂)`

### 3. Beam Search

Prunes the exponential state space by keeping only the top-N most probable states at each position.

### 4. Stream Switching Detection

Post-processing step that checks if plaintexts were swapped and corrects the assignment.

## Algorithm Complexity

- **Training**: `O(|corpus| × n)` where n=7
- **Decoding**: `O(ℓ × B × |alphabet|)` where:
  - `ℓ` = message length
  - `B` = beam width (typically 100-500)
  - `|alphabet|` = 95 (printable ASCII)

## Limitations

1. **Requires natural language text** - doesn't work on compressed/encrypted data
2. **Needs appropriate training corpus** - models must match plaintext type
3. **Computational cost** - long messages (1000+ bytes) can be slow
4. **Accuracy degrades** - errors can accumulate in very long messages

## Real-World Vulnerabilities

This attack applies to:
- Microsoft Word 2002 (RC4 IV reuse)
- 802.11 WEP (24-bit IV collision)
- WinZip encryption (keystream reuse)
- PPTP VPN (RC4 issues)
- Any AES-CTR implementation that reuses nonces

## Paper Citation
```bibtex
@inproceedings{mason2006natural,
  title={A natural language approach to automated cryptanalysis of two-time pads},
  author={Mason, Joshua and Watkins, Kathryn and Eisner, Jason and Stubblefield, Adam},
  booktitle={Proceedings of the 13th ACM conference on Computer and communications security},
  pages={235--244},
  year={2006}
}
```

## License

This is an educational implementation for academic purposes. Use responsibly.

## Acknowledgments

- Original paper by Mason et al. (ACM CCS 2006)
- Witten-Bell smoothing algorithm
- Viterbi algorithm from NLP/speech recognition

## Contributing

Feel free to open issues or submit pull requests for:
- Performance optimizations
- Additional test cases
- Documentation improvements
- Bug fixes

## Contact

[Paul-Constantin Popescu]  
[paul.popescu263@gmail.com]  
["Alexandru Ioan Cuza" University, Iasi]
[Faculty of Computer Science, MSI]

---


**Note**: This implementation is for educational and research purposes only. Do not use for malicious purposes.
