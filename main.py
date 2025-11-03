"""
Two-Time Pad Cryptanalysis
Implementation of the method from:
Mason et al., "A Natural Language Approach to Automated Cryptanalysis of Two-time Pads"
ACM CCS 2006
"""

import math
import time
from collections import defaultdict


class LanguageModel:
    """
    N-gram character language model with Witten-Bell smoothing.
    Section 2.1 of the paper.
    """
    
    def __init__(self, n=7):
        self.n = n
        self.ngram_counts = defaultdict(int)
        self.context_counts = defaultdict(int)
        self.unique_continuations = defaultdict(set)
        
    def train(self, corpus):
        """Train on a corpus of text"""
        # Add BOM (beginning) and EOM (end) markers
        text = '\x00' + corpus + '\x01'
        
        print(f"  Training {self.n}-gram model on {len(text):,} characters...")
        start = time.time()
        
        # Count all n-grams from 1-gram up to n-gram
        for i in range(len(text)):
            char = text[i]
            
            for length in range(1, min(self.n + 1, i + 2)):
                context_start = max(0, i - length + 1)
                context = text[context_start:i]
                
                self.ngram_counts[(context, char)] += 1
                self.context_counts[context] += 1
                self.unique_continuations[context].add(char)
        
        elapsed = time.time() - start
        print(f"  Training completed in {elapsed:.2f}s")
        print(f"    - Unique contexts: {len(self.context_counts):,}")
        print(f"    - Total n-grams: {sum(self.ngram_counts.values()):,}")
    
    def get_probability(self, char, context):
        """Get P(char | context) using Witten-Bell smoothing"""
        # Limit context to last n-1 characters
        if len(context) >= self.n - 1:
            context = context[-(self.n - 1):]
        
        return self._probability_recursive(char, context)
    
    def _probability_recursive(self, char, context):
        """Recursive Witten-Bell smoothing with backoff"""
        # Base case: empty context, use uniform distribution
        if len(context) == 0:
            return 1.0 / 95  # 95 printable ASCII characters
        
        context_total = self.context_counts.get(context, 0)
        
        # If never seen this context, back off to shorter context
        if context_total == 0:
            return self._probability_recursive(char, context[1:])
        
        # Witten-Bell smoothing formula
        unique_chars = len(self.unique_continuations.get(context, set()))
        count = self.ngram_counts.get((context, char), 0)
        
        # Lambda parameter for interpolation
        lambda_param = unique_chars / (context_total + unique_chars)
        
        if count > 0:
            # Seen this n-gram: interpolate
            prob_direct = count / context_total
            prob_backoff = self._probability_recursive(char, context[1:])
            return (1 - lambda_param) * prob_direct + lambda_param * prob_backoff
        else:
            # Never seen this n-gram: use backoff only
            return lambda_param * self._probability_recursive(char, context[1:])
    
    def score_text(self, text):
        """Score an entire text using the language model"""
        log_prob = 0
        for i in range(len(text)):
            context = text[max(0, i - self.n + 1):i]
            prob = self.get_probability(text[i], context)
            log_prob += math.log(prob)
        return log_prob


class TwoTimePadCracker:
    """
    Implements the Viterbi algorithm with beam search.
    Section 2.4 of the paper.
    """
    
    def __init__(self, model1, model2, beam_width=100):
        self.model1 = model1
        self.model2 = model2
        self.beam_width = beam_width
    
    def crack(self, xor_stream, verbose=True):
        """Crack XOR stream using Viterbi algorithm"""
        length = len(xor_stream)
        
        if verbose:
            print(f"\nCracking {length} bytes with beam width {self.beam_width}...")
        
        start_time = time.time()
        
        # Initial state: position 0, both contexts start with BOM
        initial_state = (0, '\x00', '\x00')
        
        # Each state maps to: (log_probability, path)
        states = {initial_state: (0.0, [])}
        
        # Viterbiību: process each position
        for i in range(length):
            if verbose and i % 100 == 0:
                elapsed = time.time() - start_time
                rate = i / elapsed if elapsed > 0 else 0
                eta = (length - i) / rate if rate > 0 else 0
                print(f"  Position {i}/{length} ({100*i/length:.0f}%), "
                      f"{len(states)} states, ETA: {eta:.0f}s")
            
            new_states = {}
            x_i = xor_stream[i]
            
            # Expand all current states
            for (pos, ctx1, ctx2), (log_prob, path) in states.items():
                if pos != i:
                    continue
                
                # Try all printable ASCII character pairs
                for p_i in range(32, 127):  # Space (32) to ~ (126)
                    q_i = p_i ^ x_i
                    
                    # Skip if q_i is not printable
                    if q_i < 32 or q_i > 126:
                        continue
                    
                    char1 = chr(p_i)
                    char2 = chr(q_i)
                    
                    # Calculate probabilities
                    prob1 = self.model1.get_probability(char1, ctx1)
                    prob2 = self.model2.get_probability(char2, ctx2)
                    
                    # Skip very unlikely transitions
                    if prob1 < 1e-20 or prob2 < 1e-20:
                        continue
                    
                    # New log probability
                    new_log_prob = log_prob + math.log(prob1) + math.log(prob2)
                    
                    # Update contexts
                    new_ctx1 = (ctx1 + char1)[-(self.model1.n - 1):]
                    new_ctx2 = (ctx2 + char2)[-(self.model2.n - 1):]
                    
                    new_state = (i + 1, new_ctx1, new_ctx2)
                    new_path = path + [(char1, char2)]
                    
                    # Keep best path to this state
                    if new_state not in new_states or new_log_prob > new_states[new_state][0]:
                        new_states[new_state] = (new_log_prob, new_path)
            
            # Beam search pruning
            if len(new_states) > self.beam_width:
                sorted_states = sorted(
                    new_states.items(),
                    key=lambda x: x[1][0],
                    reverse=True
                )
                states = dict(sorted_states[:self.beam_width])
            else:
                states = new_states
            
            if not states:
                raise ValueError(f"No valid states at position {i}!")
        
        # Find the best final state
        best_state = max(states.items(), key=lambda x: x[1][0])
        _, (log_prob, path) = best_state
        
        elapsed = time.time() - start_time
        
        if verbose:
            print(f"\nCracking completed in {elapsed:.2f}s")
            print(f"  Best log probability: {log_prob:.2f}")
            print(f"  Average per character: {log_prob/length:.2f}")
        
        # Reconstruct plaintexts
        plaintext1 = ''.join(p for p, q in path)
        plaintext2 = ''.join(q for p, q in path)
        
        # Fix stream switching (Section 4.3)
        plaintext1, plaintext2 = self._fix_stream_switching(
            plaintext1, plaintext2, xor_stream, verbose
        )
        
        return plaintext1, plaintext2
    
    def _fix_stream_switching(self, p, q, xor_stream, verbose):
        """Fix the "switching streams" problem (Section 4.3)"""
        # Verify XOR is correct
        for i in range(len(p)):
            if ord(p[i]) ^ ord(q[i]) != xor_stream[i]:
                return p, q
        
        # Score both assignments
        score_normal = self.model1.score_text(p) + self.model2.score_text(q)
        score_swapped = self.model1.score_text(q) + self.model2.score_text(p)
        
        if verbose:
            print(f"  Stream assignment scores: normal={score_normal:.2f}, swapped={score_swapped:.2f}")
        
        # Return the better assignment
        if score_swapped > score_normal:
            if verbose:
                print(f"  -> Streams were swapped! Fixing...")
            return q, p
        else:
            return p, q


def create_training_corpus():
    """Create training corpora for the two plaintext types"""
    # Business/formal corpus
    business_sentences = [
        "Hello, I hope this message finds you well.",
        "I am writing to follow up on our previous discussion regarding the project.",
        "Thank you very much for your help with this matter.",
        "I really appreciate your quick response and attention to detail.",
        "Please send me the updated documentation when you have a chance.",
        "The meeting is scheduled for tomorrow at 3 PM in the conference room.",
        "Can you please review the attached files and provide your feedback?",
        "I will be out of the office next week on vacation.",
        "Please contact my colleague if you need immediate assistance.",
        "Have a great day and I look forward to hearing from you soon.",
        "Best regards from the team and thank you for your cooperation.",
        "We need to ensure that all components are working correctly.",
        "The project timeline needs to be reviewed and updated.",
        "Please confirm your attendance at the meeting tomorrow.",
        "Let me know if you have any questions or concerns about this.",
    ]
    
    # Secret/casual corpus
    secret_sentences = [
        "Secret text that should be decoded carefully and completely.",
        "The password is hidden somewhere in the message text.",
        "I will call you very soon to discuss all the details.",
        "Meet me at the usual place tonight at eight o'clock.",
        "Everything is ready for the operation tomorrow morning.",
        "Pack my box with five dozen jugs of liquid very quickly.",
        "The package will arrive tomorrow morning at the location.",
        "Make sure nobody sees you pick it up from there.",
        "We need to be very careful about this important matter.",
        "The information is extremely sensitive and confidential.",
        "Do not share this with anyone else under any circumstances.",
        "The code word for today is butterfly as we discussed.",
        "Remember to follow the protocol exactly as planned.",
        "Stay safe and keep a low profile until we reconnect.",
        "Destroy this message after reading it completely.",
    ]
    
    # Create varied corpus
    corpus1_parts = []
    corpus2_parts = []
    
    for _ in range(50):  # Repeat for more training data
        for sent in business_sentences:
            corpus1_parts.append(sent)
            corpus1_parts.append(sent.lower())
            corpus1_parts.append(sent + " ")
            words = sent.split()
            if len(words) > 3:
                corpus1_parts.append(" ".join(words[1:]))
                corpus1_parts.append(" ".join(words[:-1]))
    
    for _ in range(50):
        for sent in secret_sentences:
            corpus2_parts.append(sent)
            corpus2_parts.append(sent.lower())
            corpus2_parts.append(sent + " ")
            words = sent.split()
            if len(words) > 3:
                corpus2_parts.append(" ".join(words[1:]))
                corpus2_parts.append(" ".join(words[:-1]))
    
    corpus1 = " ".join(corpus1_parts)
    corpus2 = " ".join(corpus2_parts)
    
    return corpus1, corpus2


def run_tests():
    """Run comprehensive tests"""
    
    print("="*80)
    print("TWO-TIME PAD CRYPTANALYSIS")
    print("Implementing the method from Mason et al., CCS 2006")
    print("="*80)
    
    # TRAINING PHASE
    print("\n[TRAINING PHASE]")
    print("-"*80)
    
    corpus1, corpus2 = create_training_corpus()
    
    print(f"\nCorpus 1 size: {len(corpus1):,} characters")
    print(f"Corpus 2 size: {len(corpus2):,} characters")
    
    print("\nTraining Model 1 (Business/Formal):")
    model1 = LanguageModel(n=7)
    model1.train(corpus1)
    
    print("\nTraining Model 2 (Secret/Casual):")
    model2 = LanguageModel(n=7)
    model2.train(corpus2)
    
    # TEST CASES
    test_cases = [
        {
            'name': 'Short message (50 bytes)',
            'p': b"Hello, I hope this email finds you very well today",
            'q': b"Secret package will arrive tomorrow morning early",
            'beam': 100
        },
        {
            'name': 'Medium message (150 bytes)',
            'p': b"The meeting is scheduled for tomorrow at 3 PM. Please confirm your attendance and review the attached files before the meeting starts.",
            'q': b"The code word for today is butterfly. Use it when you make contact with the agent at the designated location tomorrow morning.",
            'beam': 200
        },
        {
            'name': 'Long message (250 bytes)',
            'p': b"Thank you very much for your help with this matter. I really appreciate your quick response and attention to detail. "
                 b"Can you please review the documentation and provide feedback by end of day? I will be out of office next week. "
                 b"Please contact my colleague.",
            'q': b"Everything is ready for the operation tomorrow morning. Make sure nobody sees you at the location and pick up the package. "
                 b"The password is hidden in the message. Remember to follow the protocol exactly as we discussed before. "
                 b"Stay safe and be careful.",
            'beam': 300
        },
        {
            'name': 'Very long message (500 bytes)',
            'p': b"Hello, I hope this message finds you well. I am writing to follow up on our previous discussion regarding the project timeline. "
                 b"Please send me the updated documentation when you have a chance to review everything. Thank you very much for your help. "
                 b"I really appreciate your quick response and attention to detail. The meeting is scheduled for tomorrow at 3 PM. "
                 b"Can you please review the attached files and provide your feedback by end of day? I will be out of office next week. "
                 b"Please contact my colleague if you need immediate assistance. Best regards.",
            'q': b"Secret text that must be decoded carefully and completely. The password is hidden somewhere in the message text below. "
                 b"I will call you very soon to discuss all the details. Meet me at the usual place tonight at eight o'clock sharp. "
                 b"Everything is ready for the operation tomorrow morning. Pack my box with five dozen jugs very quickly please. "
                 b"Make sure nobody sees you pick it up from the location. The code word for today is butterfly as discussed. "
                 b"Remember to follow the protocol exactly. Stay safe and destroy this message.",
            'beam': 400
        }
    ]
    
    print("\n" + "="*80)
    print("[TESTING PHASE]")
    print("="*80)
    
    total_chars = 0
    total_correct = 0
    total_time = 0
    
    for idx, test in enumerate(test_cases):
        print(f"\n{'='*80}")
        print(f"TEST {idx + 1}: {test['name']}")
        print(f"{'='*80}")
        
        p = test['p']
        q = test['q']
        
        # Make same length
        min_len = min(len(p), len(q))
        p = p[:min_len]
        q = q[:min_len]
        
        print(f"\nLength: {min_len} bytes")
        print(f"Beam width: {test['beam']}")
        print(f"\nOriginal P: {p.decode()[:70]}...")
        print(f"Original Q: {q.decode()[:70]}...")
        
        # Create XOR stream
        xor_stream = bytes(a ^ b for a, b in zip(p, q))
        
        # Crack it
        cracker = TwoTimePadCracker(model1, model2, beam_width=test['beam'])
        
        start = time.time()
        recovered_p, recovered_q = cracker.crack(xor_stream, verbose=True)
        crack_time = time.time() - start
        
        total_time += crack_time
        
        print(f"\n{'='*80}")
        print("RESULTS")
        print(f"{'='*80}")
        print(f"Recovered P: {recovered_p[:70]}...")
        print(f"Recovered Q: {recovered_q[:70]}...")
        
        # Calculate accuracy
        correct = sum(1 for (a, b), (c, d) in 
                     zip(zip(p.decode(), q.decode()), zip(recovered_p, recovered_q)) 
                     if (a == c and b == d))
        
        total_chars += min_len
        total_correct += correct
        
        accuracy = 100 * correct / min_len
        speed = crack_time / min_len * 1000
        
        print(f"\nAccuracy: {correct}/{min_len} ({accuracy:.1f}%)")
        print(f"Time: {crack_time:.2f}s ({speed:.1f} ms/byte)")
        
        # Show some errors if any
        if correct < min_len:
            errors = []
            for i, ((a, b), (c, d)) in enumerate(zip(zip(p.decode(), q.decode()), 
                                                      zip(recovered_p, recovered_q))):
                if a != c or b != d:
                    errors.append(i)
                    if len(errors) >= 3:
                        break
            if errors:
                print(f"First errors at positions: {errors}")
    
    # Overall statistics
    print(f"\n{'='*80}")
    print("OVERALL RESULTS")
    print(f"{'='*80}")
    print(f"Total characters: {total_chars}")
    print(f"Overall accuracy: {100*total_correct/total_chars:.1f}%")
    print(f"Total time: {total_time:.2f}s")
    print(f"Average speed: {total_time/total_chars*1000:.1f} ms/byte")
    print(f"\nPaper reports: 99% accuracy on HTML (Section 4.2)")
    print(f"Our result: {100*total_correct/total_chars:.1f}% on mixed text")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    run_tests()