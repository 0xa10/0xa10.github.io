---
layout: post
title:  "need-feedback - Google CTF 2016 challenge writeup"
date:   2018-11-27 07:47:31 -0600
tags: crypto ctf challenge sbox linear cryptanalysis lfsr algebra 
---
* Table of Contents
{:toc}

## Intro
In this write-up I’ll present my solution to the need-feedback challenge from the 2016 Google CTF “Homework” exercises.  
I mainly wanted to try and make some of the mathematical concepts involved in the solution more accessible and intuitive for anyone who has an interest in crypto, but not much of a formal mathematical background.

A big thank you goes out to @Bar Katz for introducing me to the mathematical theory and intuition required to tackle this task, over 2 years ago.

## need-feedback
You can find the original challenge file (a tar archive) [here][original-challenge-link]. 
Once extracted, you are presented with some code, and a pcap file.

![Challenge files](/images/challenge_files.png){:width="250px"} ![Included capture](/images/pcap_screenshot.png){:width="450px"}  
The code seems to implement some sort of secure channel, tunneling and encrypting access to an HTTP server. The secret itself is a 20 part file. This corresponds to the capture file, which contains 20 plaintext requests and encrypted responses - our goal is to decrypt those responses.

While the challenge itself remained unsolved during the CTF, a [solution][luc-lynx-writeup] was written up by @luc-lynx slightly after the CTF ended.
In his solution, @luc-lynx utilized a meet-in-the-middle technique to reduce the keyspace to approx. `2^43`. According to the write-up, revealing the key took about 3 days. 
In my solution, I wanted to reduce the time required to recover the key to an amount of time feasible in the timespan of the CTF.

To accomplish this, I had to learn and utilize a variety of techniques aimed at unraveling some of the cipher’s underlying components - namely the Sbox and pseudo-random number generator.    This write-up, hopefully, will serve as an intuitive introduction into some more advanced aspects of crypto, including but not limited to buzzwords such as:
* Linear feedback shift registers 
* Linear cryptanalysis
* Sbox analysis
* Linear equation systems
* Gaussian elimination
* Cold fusion

## KappaCrypto
![Challenge files](/images/cipher_design.png) <center><i>Overview of the KappaCrypto cipher system</i></center>  
The cipher system presented in the challenge is called `KappaCrypto`.
It comprises several components - a `KappaTunnelHandler` class implements an interface for a basic Python `ThreadedTCPServer`.
Inside the tunnel, a `KappaChannel` object is instantiated, which processes messages in the upstream and downstream channels, wrapping them in `KappaMsg` objects, and then serializing them into `KappaPacket` objects which are finally sent through the tunnel.

The encryption takes place prior to wrapping in `KappaMsg` objects, using the `KappaCrypto` class, which has 3 major components:
1. 5 sets of coefficients for LFSRs in various bit lengths.
2. An Sbox, implemented as a simple Python list.
3. A MultiLFSR class, which combines the outputs of the aforementioned LFSRs before passing the result through the S-box. 

**LFSR** stands for [linear feedback shift register][lfsr-wiki], and is a simple pseudorandom number generator, which emits a single bit each round.

**Sbox** stands for [Substition-box][sbox-wiki] is simply a construct which takes in values in a given range and outputs values in a given range. More on the purpose of the Sbox in the next segments.

`KappaCrypto` takes these two basic cryptographic constructs and chains them together within the MultiLFSR class - which is responsible for taking in a seed and outputting a keystream with which the plaintext is XORed.     

```python
140   # symmetric
141   def proc(self, msg, is_enc):
142     self.count += len(msg)
143     
144     msg2 = bytearray(msg)
145     for i in range(len(msg2)):
146       for k in range(8):
147         msg2[i] ^= self.mlfsr.next() << k
148     return msg2
149     #return bytes([a ^ 72 for a in msg])
``` 
<center><i>Excerpt from channel.py - MultiLFSR class </i></center>  
    
  
The `MultiLFSR` is seeded by hashing a key and initialization vector (initialized to 0) to generate enough random bits to fill all the LFSR states.
The cipher system supports reseeding by incrementing the IV value, but luckily for us, the code indicates that this feature remains unimplemented:

```python
291   def proc_reseed(self, e):
292     assert 0, "unimplemented"
293     pass
```
<center><i>Excerpt from channel.py - KappaChannel class</i></center>  
  

To recap - we are provided with code for a cipher system comprising 5 LFSRs with fixed coefficients, the output of which is combined and passed through an Sbox.
We are also provided with a pcap file containing an encrypted session, and we want to recover the original state bits for each of the LFSRs, totalling 60 bits, in a reasonable amount of time.

![Coefficient count](/images/coeff_count.png){:height="40px"}<center><i>Sum of all LFSR lengths</i></center>  

## Linear feedback shift registers
LFSRs are simple PRNG constructs, which are commonly used in hardware applications due to their speed and simplicity.
LFSRs are used (to varying degrees of security) in many ciphers, such as the ones implemented in GSM, Bluetooth, and various digital broadcast mediums.

A famous example - the [Content Scramble System][css-wiki], which was used to encrypt DVDs and was implemented using LFSRs, was [completely broken][css-wiki-hack] partially on account of its use of LFSRs.

Many types of LFSRs exist, the one implemented in `KappaCrypto` most closely resembles a [Galois LFSR][galois-lfsr-wiki].
Let’s take a look at the code:  
```python
41 def __init__(s, coeffs, n, state=1):
42     poly = 0
43     for j in coeffs:
44       poly |= 1 << j
45     self.coeffs = coeffs
46     self.poly = poly
47     self.n = n
48     self.state = state
```
```python
127 lfsr = LFSR(coeffs, coeffs[-1])
```
```python

50   def next(self):
51     b = self.state >> (self.n - 1)
52     self.state = self.state << 1
53     assert b == 0 or b == 1
54     if b:
55       self.state ^= self.poly
56     return b
```

<center><i>Excerpts from channel.py - LFSR class methods and example of instantiation</i></center>
  
The LFSR is initialized with a **coefficient** vector corresponding to an n bit register. The **state** parameter is effectively the seed.
The LFSR is shifted each round, the MSB becomes the output bit, and a zero bit is inserted as the LSB. The coefficient vector marks "taps" on the LFSR, which are XORed with the output bit in each round.

{:text-align="center"}
![LFSR schematic](/images/lfsr_schema.png)<center><i>A 10 bit LFSR, with taps at 0,1,2,3,6,9,0xa</i></center>  


Note that the MSB is XORed with itself at the output bit position, which causes the register to be naturally truncated at its bit length each round, as any `1` bit that reaches the output position will  be nulled. This is just an implementation choice since Python integers are of arbitrary length.  

This construct is linear - the state of the LFSR (and its outputs) can be represented as a linear function or combination of the previous state bits.
Practically - any output from the LFSR can be expressed as a combination (e.g. addition modulo 2) of some of its initial state bits, i.e. the **seed**.  

This means that we can construct equations to represent the output bits at any round. Given enough outputs from the actual LFSR, we can recover the initial state/seed value.
Generally speaking - to recover the initial state for an n-bit LFSR, we need n outputs generated from that seed.
We can then construct a [system of equations][les-wiki] (same as the ones you were taught in school), where each of the LFSRs bits is a variable, and the solution is the initial state.

To illustrate the intuition behind this, let’s go over a simple example, of a 4-bit toy-LFSR A, with the following coefficients: `[0x1, 0x2, 0x4]`. We want to illustrate that each output of the LFSR is actually a linear combination of some of its initial state bits: 

![LFSR step 1](/images/lfsr_step1.png)
![LFSR step 2](/images/lfsr_step2.png)
![LFSR step 3](/images/lfsr_step3.png)
![LFSR step 4](/images/lfsr_step4.png)

Say we are given 4 consecutive outputs from the register - `[1, 0, 1, 1]`, we can assemble a linear equation system, subbing the XOR operation with addition modulo 2. We can then assign and solve for all indeterminates:

|``` a3        ≡ 1 mod 2  
a2      ≡ 0 mod 2  
a1 + a3 ≡ 1 mod 2  
a0 + a3 + a2    ≡ 1 mod 2``` | blah | blah |

According to this, the initial state vector `[a0,a1,a2,a3]` was `[0,0,0,1]`, or the value 8.  
We can verify this using the KappaCrypto LFSR code:  

![LFSR example](/images/lfsr_example.png){:width="400px"}
  

To generalize this process for any LFSR, we can utilize [Matrices][matrix-wiki]:  
Another way to look at the above equation system is as a set of polynomials over `GF(2)` of the form `c0·a0 + … + cn·an`, meaning each ‘bit’ position has a coefficient that’s either `0` or `1`.

1·a3 + 0·a2 + 0·a1 + 0·a0 ≡ 1 mod 2
0·a3 + 1·a2 + 0·a1 + 0·a0 ≡ 0 mod 2
1·a3 + 0·a2 + 1·a1 + 0·a0 ≡ 1 mod 2
1·a3 + 1·a2 + 0·a1 + 1·a0 ≡ 1 mod 2
matrix table here
> On the left - the original equation system. On the right, an equivalent matrix representation, in which C is the coefficient matrix and S is the result vector.  

The linear equation system (in matrix form) can then be solved with Gaussian Elimination or any other method of reducing the matrix to its echelon form - in this case I let Sagemath do the heavy lifting: 
![Sagemath solution example](/images/sagemath_solution.png)<center><i>Since the matrix rank is full-rank, we can solve for all 4 variable columns.</i></center>  

  
Now, to generalize this, we want to be able to generate systems of equations for any LFSR of length n, that we can join with an n element output vector to solve for the original seed.
The general concept and notation for this can be found [here][lfsr-article], though I did have to port some of these concepts to apply on the `KappaCrypto` LFSR.
  
Eventually, I ended up with a function that takes in an LFSR (or more specifically, its coefficient vector, in tap form) and outputs a set of linear equations describing its outputs:
```python
def make_lfsr_equations(coefficients, count):
    n = len(coefficients)
    shift_matrix = matrix(GF(2), n,1).augment(matrix.identity(n)[:,:n-1]) # right shift 
    coeff_matrix = matrix(GF(2), n-1, n).stack(matrix(GF(2), coefficients))
    tmp = matrix.identity(n)
    eqs = matrix(GF(2), count, n)
    for i in range(count):
        eqs[i] = tmp[:, -2].transpose() # Column for second to most significant bit
        tmp = tmp*shift_matrix + tmp*shift_matrix*coeff_matrix
    return eqs
```

<center><i>Sage code for generating LFSR equations</i></center>  
![Sage LFSR example](/images/sagemath_lfsr_example.png)<center><i>Example of output for the toy-LFSR from before - note that rightmost column is actually the output bit, and is redundant.
Below that, the generated equations are multiplied with the seed vector to generate the LFSRs outputs. 
</i></center>  
  
To clarify - each row in the resulting matrix represents a linear combination of some of the initial state bits - same as the linear equation system from before. 
To get the LFSRs **nth** output, we can transpose and multiply the **nth** row with the initial state vector. Similarly, we can multiply an **n** row matrix with the initial state vector to get **n** consecutive outputs.


In our case we will be using the generated equations along with the output vector to solve for the initial state vector.   
Here’s an example using one of the LFSRs from *KappaCrypto*:

![Sagemath LFSR solution](/images/sagemath_lfsr_solution.png)<center><i>s is a 10 outputs of a 10-bit LFSR initialized to the value 304.</i></center>



## Multi-LFSR
The next component in *KappaCrypto* is the *MultiLFSR* class - this class bands together an arbitrary amount of LFSRs with different polynomials and seeds, and combines their outputs by XORing them together. 
It’s also responsible for passing them through the *Sbox*, but more on that later.    
Given that we already know how to represent an LFSRs output bits as linear combinations of its state bits, and that XORing those output bits is simply addition modulo 2, we can represent the *MultiLFSRs* output bits as linear combinations of all its LFSRs state bits. 
  
To illustrate this, let’s return to our toy-LFSR A from before, this time with an additional 5 bit toy-LFSR B in the mix. It’s coefficients will be `[0x0,0x1,0x3,0x4,0x5]` and its state bits will be represented as `b0,b1,b2,b3,b4`. When seeded to 12, the first 5 outputs are `[0,1,0,1,1]`.

TODO - insert table here
  
We can add the equation systems together to obtain a linear equation system with twice the variables. To solve this newly assembled equation system, which now has 9 variables, we need 9 output bits.
Adding the equation systems together can represented by stacking their matrices.

-
![Sagemath MultiLFSR solution](/images/sagemath_multilfsr_solution.png)<center><i>sa, sb are 9 outputs from the two toy-LFSRs above. By stacking the two LFSR equation sets horizontally (augmenting) and setting the results vector to a be the combination of both output vectors, we can solve for both initial state vectors - 8 and 12.</i></center>
-

In other words, the *MultiLFSR* construct is still fully linear, and we can still represent its outputs as linear combinations of the initial state bits, and recover them given enough outputs.
More concretely, for a *MultiLFSR* containing LFSRs with a total of **N** bits between them, we need **N** outputs to recover the original state.
This component doesn’t really add any significant strength to the cipher system, and may even be worse than a normal LFSR with the equivalent bit length.



  
## Substitution boxes and linear cryptanalysis
As we’ve seen, LFSRs by themselves do not offer a great deal of security for block ciphers. The linear relationship between their inputs and outputs make it easy to reverse their action and solve for the indeterminate or key bits.
This is where the Sbox comes in - an Sbox is a component which maps from n to m bit values, with the purpose of reducing linearity, to some extent obstructing our use of linear equation systems.
  
In KappaCrypto, the Sbox maps from 6 bit inputs to 4 bit outputs, meaning each output is associated with 22 = 4 inputs. The lossiness is what makes it hard for us to reverse the Sbox - given an arbitrary 4 bit output from the Sbox, there are 4 different inputs which could have led to that output value. 
  

The Sbox is put to use in the MultiLFSR class - every 6 bits of outputs from the MultiLFSR (generated in 6 rounds of the comprised LFSRs) are concatenated to form a 6 bit word, which is then used as input for Sbox.
  
To recap our problem - prior to passing through the Sbox we could represent the keystream as linear combinations of the key/seed bits - but the Sbox prevents us from doing that, since its action cannot be naively represented with linear equations. 
  
In order to overcome this obstacle, we need to find linear equations which hold over the Sbox function - in other words, find relations between the inputs bits which “survive” being put through the Sbox.
More concretely, given a certain 4 bit output, we want to look at all 4 input values which could have led to it, and find linear equations which hold over all of them.
  
To do this, we’ll need to take a closer look at the Sbox, at the bit level.
We'll start off with an intuitive example, working on the Sbox from KappaCrypto:
```python
sbox_tb = [ 7, 6, 5, 10, 8, 1, 12, 13, 6, 11, 15, 11, 1, 6, 2, 7, 0, 2,
                    8, 12, 3, 2, 15, 0, 1, 15, 9, 7, 13, 6, 7, 5, 9, 11, 3, 3,
                    12, 12, 5, 10, 14, 14, 1, 4, 13, 3, 5, 10, 4, 9, 11, 15, 10,
                    14, 8, 13, 14, 2, 4, 0, 0, 4, 9, 8,]
```
<center><i>In KappaCrypto, the Sbox is a simple lookup table in the form of a list - the index is the input value.</i></center>

First, we want to reverse the Sbox to see which outputs are caused by which 4 inputs:
```python
rev_sbox_tb = defaultdict(list) 
        for idx, value in enumerate(sbox_tb):
            rev_sbox_tb[value].append(idx)
        rev_sbox_tb
        defaultdict(list,
            {7: [0, 15, 27, 30],
             6: [1, 8, 13, 29],
             ... (truncated)
             14: [40, 41, 53, 56],
             4: [43, 48, 58, 61]})
```
<center><i>Mapping between output values to their index (input value) in the list.</i></center>
 
 


  
Taking output value `7` as an example - it substitutes input values `0,15,27,30`. Let’s look at the binary representation for all these values:
![Sbox bit forms](/images/sbox_bit_forms_7.png)<center><i>bv() simply returns the bit representation for a given value, padding to n bits.></i></center>
  
Looking at each “column” of bits in the input values, from left to right, we observe the following:
* In columns 2,4,5,6 of each of the values, there’s an even occurrence of `0` and `1` bits.
* In column 3, 0 only occurs once, and `1` occurs 3 times.
* In column 1 - **only** `0` bits occur!
This shows a significant bias in the Sbox - the MSB in each input value leading to output value `7` is `0` in 4 out of 4 cases. 

Given this new information, lets say we observe the Sbox output the value `7`. At the most basic level, we know the four inputs which could have led to this value, with each input value having (ostensibly) a 1 in 4 chance of causing this output value. This doesn’t help us much. But we also know, regardless of the correct input value out of the 4, that its MSB was `0`.
  
The forms the basis for our solution - we want to try and find single bits, or linear combinations of bits from the input values, which have strong or even absolute biases with regards to a certain output value. For the purpose of this solution I won’t be using the non-absolute biases, since they complicate things significantly and the challenge can be solved without using them.

![Sbox bit forms](/images/sbox_bit_forms_14.png)<center><i>Another example, for output value 14 - here bits 1 and 5 have 100% bias, and bits 3 and 4 have 75% bias.</i></center>

  
To generalize this one step further, we’re going to utilize [boolean functions][bool-funcs-wiki] (i.e. functions that return either `0` or `1`) that take the 6 input bits `x1,x2,x3,x4,x5,x6` as parameters and return a linear combination of them (i.e. addition modulo 2).
For instance, `x1 + x3 + x4` is a boolean function which combines the first, third, and fourth bits. 
Our goal is to find all such boolean functions that have the same result over all 4 input values leading to a specific output value. 
Looking at the 4 input values for output value `14` again, and applying the boolean function `x1 + x3 + x4` on each of them, we end up with the following equations
```
x1 + x3 + x4(101000) = 1 + 1 + 0 ≡ 0 mod 2
x1 + x3 + x4(101001) = 1 + 1 + 0 ≡ 0 mod 2
x1 + x3 + x4(110101) = 1 + 0 + 1 ≡ 0 mod 2
x1 + x3 + x4(111000) = 1 + 1 + 0 ≡ 0 mod 2
```
  
This means that for the output value `14`, the boolean equation `x1 + x3 + x4 = 0` holds *100%* of the time. Recall that `x1...xn`, the input bits to the *Sbox*, are in fact the output bits from the *MultiLFSR*, and as such we can represent them as linear combinations of the state bits. 
So we’ve effectively found a linear equation which holds over the Sbox for a certain output, and can be expressed using the key/seed bits.
  
Another example of a linear equation which holds over the Sbox for output value `14` is  `x3 + x4 + x5 = 1`:
```
x3 + x4 + x5(101000) = 1 + 0 + 0 ≡ 1 mod 2
x3 + x4 + x5(101001) = 1 + 0 + 0 ≡ 1 mod 2
x3 + x4 + x5(110101) = 0 + 1 + 0 ≡ 1 mod 2
x3 + x4 + x5(111000) = 1 + 0 + 0 ≡ 1 mod 2
```
  
Finding all such boolean functions is simple - consider the following representation for the above boolean functions:
```
x1 + x3 + x4 =  1·x1 + 0·x2 + 1·x3 + 1·x4 + 0·x5 + 0·x6
x3 + x4 + x5 =  0·x1 + 0·x2 + 1·x3 + 1·x4 + 1·x5 + 0·x6
```

If we separate the coefficients, we get two 6 bit vectors `[1,0,1,1,0,0]` and `[0,0,1,1,1,0]`. 
Alternatively, we can look at these vectors as 6 bit mask values - `101100` (44) and `001110` (14). Either way it’s simple to see that there are only 2^6 such masks or boolean functions.
If we opt to represent the boolean functions as masks, then the result of the boolean function can be obtained by applying the mask (by ANDing) on a 6 bit value, and then summing the bits modulo 2:
```
101100 & 101000 = 101000
    H(101000) = 1 + 0 + 1 + 0 + 0 + 0 ≡ 0 mod 2
101100 & 101001 = 101000
    H(101000) = 1 + 0 + 1 + 0 + 0 + 0 ≡ 0 mod 2
101100 & 110101 = 100100
    H(101000) = 1 + 0 + 1 + 0 + 0 + 0 ≡ 0 mod 2
101100 & 111000 = 101000
    H(101000) = 1 + 0 + 1 + 0 + 0 + 0 ≡ 0 mod 2
```
<center><i>H(x) is the Hamming weight (count of 1 bits aka sum of the bits).</i></center>

To implement our solution, we take each possible Sbox output, and map its 4 corresponding input values. 
For those 4 input values, we iterate over all possible 2^6 masks, apply them to each input value, and sum the results bits modulo 2. If all 4 results are the same, we’ve successfully found a linear equation which holds over the Sbox, and we set it aside.To recap - for each given Sbox output value, and the four corresponding inputs,
This logic is implemented in the `get_sbox_equations` function in the solution code.
  
![Sbox equations](/images/sbox_equations.png)<center><i>Example output from get_sbox_equations - for output value 5, there are 7 boolean functions, which are represented as their mask value - e.g. the mask value 010011 (19) results in 1, meaning the linear equation x2 + x5 + x6  ≡ 1 mod 2 holds over output value 5.</i></center>
  
Eventually, about 128 such boolean functions exist which holds over the *KappaCrypto* Sbox.
This means, that for each known output from the LFSR, we gain on average 8 linear equations that hold over the entire cipher, and go toward solving the initial state vectors of the LFSRs.      
Note that some of these equations may be linearly dependant and as such redundant, but we are still gleaning a significant amount of data from each known Sbox output - which is in fact the keystream.
  
  
## Putting it all together

We’ve chained together several components, and managed to establish linear relationships between the initial state values (i.e. the key/secret) and the keystream. 
Let’s recap our process:
We have equations that hold over the Sbox, their parameters are the 6 Sbox input bits - `x1,x2,x3,x4,x5,x6`.
Recall that the 6 Sbox input bits are in fact 6 outputs from the *MultiLFSR*, and that each of those 6 outputs is actually the sum of all 5 LFSRs in a single round.
Formally - If `Li,j` is the jth round output from the ith LFSR, then the *MultiLFSRs* output in the jth round is:

```
Li,j= L1,j+L2,j+L3,j+L4,j+L5,j = xj%6
```
  
Li,j, being the LFSRs output, can be represented as a linear combination of the ith LFSR initial state bits - its the jth equation obtained from our code from the first section.
  
At this point we can start assembling linear equations that have all the LFSRs N initial state bits as variables, and hold over the cipher given specific Sbox outputs - i.e. the keystream.
More concretely, we can stage a [known-plaintext attack][kpa-wiki] (or a [correlation attack][correlation-attack-wiki]), given we know the ciphertext and plaintext bytes (crib). 

![Wireshark view of capture](/images/wireshark_cap.png)<center><i>The request and response are prefixed with KappaMsg headers - Size (in orange) and MsgType (in turquoise)</i></center>
  
Since the upstream channel is unencrypted, we can see that the underlying protocol being tunneled through *KappaCrypto* is simply HTTP.
Since the request structure is that of a valid HTTP request, it's safe to assume the response will be a valid HTTP response - meaning it starts with something along the lines of `'HTTP/1.0 200 OK'`, setting aside error codes and HTTP versions for now.
  
With this knowledge, we can retrieve `len(‘HTTP/1.0 200 OK')` worth of keystream from each response, simply by stripping the *KappaMsg* header from the first block, and XORing the ciphertext with the crib.
  
Once we have our keystream bytes, we can divide them into 4 bit nibbles - each nibble is an Sbox output. 
For each Sbox output, we refer to our Sbox equations for that output, and expand them using the equations representing the *MultiLFSR* outputs, which are composed of variables representing the 60 bits from all 5 LFSRs.
We continue doing this until we collect 60 linearly independent equations, and then solve for the original seed value.
If our crib guess was wrong (wrong HTTP version, for instance), we will most likely not come up with a valid solution, and can try again with a different guess.

It’s worth noting that the guessed keystream doesn't have to be contiguous - we can guess just a few bytes (e.g. just `'HTTP'`) from each of the 20 responses.

Once we have the original seed values, we simply instantiate a *KappaCrypto* object and inject the seed values into all 5 LFSRs, and continue to decrypt the payload.
![Solution example](/images/solution_example.png)<center><i>The solution, showing the recovered LFSR states, recovered in a matter of seconds.</i></center>
  
  
  
![The flag](/images/the_flag.png)<center><i>The flag (cropped) is embedded in a 3548 x 3547 15MB PNG file</i></center>

I’ll refer you to the solution code for further details. Note that while most of the code samples in this write up are in Sagemath (for brevity and clarity’s sake), I opted to implement the full solution in Python3 + numpy (for portability’s sake).
I also opted to implement some of the matrix operations (such as Gaussian Elimination) myself since numpy was being difficult with non-square matrices.
[todo - gaussian elimination animation]

Overview of the attack process:
1. For all LFSRs in the MultiLFSR system, generate equations representing each output bit from the MultiLFSR, prior to passing through the Sbox.
2. For all Sbox outputs, search for boolean functions representing linear equations that hold over said Sbox input to output mapping.
3. Using HTTP headers as presumed plaintext, guess some of the keystream values.
4. For each nibble in the keystream, collect all the boolean functions found for that nibble value.
a. For each nibble value and its respective boolean functions/mask, take 6 MultiLFSR equations (representing 6 MultiLFSR outputs) and XOR together the equations for which the relevant bit in the mask was 1
b. Set the equations result to be the result of said boolean function. This will result in a N variable equation, with an additional result bit - set it aside.
5. When N linearly-independent equations are collected, stack them to create an Nx(N+1) matrix representing a linear equation system.
6. Solve using Gaussian Elimination. The output should be an NxN identity matrix along with an N bit solution column representing the initial state of all bits in the MultiLFSR.
7. Using those seed values, decrypt the communications. 

Further reading:
https://www.springer.com/gp/book/9783642173417
https://www.iasj.net/iasj?func=fulltext&aId=88499
https://www.rocq.inria.fr/secret/Anne.Canteaut/poly.pdf





TODO - 
    tables for equations
    subscripts for equations, superscript for powers, ith superscript
    math symbol sum
    center images
    redo some drawing
    add matrix representation near lfsr polynomials



[original-challenge-link]: https://github.com/ctfs/write-ups-2016/blob/39e9a0e2adca3a3d0d39a6ae24fa51196282aae4/google-ctf-2016/homework/need-feedback-300/47799aaf18a96cc17b3dd665d857a44921fb928f91b6fb2a54aaee6c28efaa8a
[luc-lynx-writeup]: https://github.com/luc-lynx/need_feedback_writeup/blob/master/README.md
[lfsr-wiki]: https://en.wikipedia.org/wiki/Linear-feedback_shift_register
[sbox-wiki]: https://en.wikipedia.org/wiki/S-box
[css-wiki]: https://en.wikipedia.org/wiki/Content_Scramble_System
[css-wiki-hack]: https://en.wikipedia.org/wiki/Content_Scramble_System#Cryptanalysis
[galois-lfsr-wiki]: https://www.nayuki.io/page/galois-linear-feedback-shift-register
[les-wiki]: https://en.wikipedia.org/wiki/System_of_linear_equations
[matrix-wiki]: https://en.wikipedia.org/wiki/System_of_linear_equations#Matrix_solution
[lfsr-article]: https://www.iasj.net/iasj?func=fulltext&aId=88499
[bool-funcs-wiki]: https://en.wikipedia.org/wiki/Boolean_function
[kpa-wiki]: https://en.wikipedia.org/wiki/Known-plaintext_attack
[correlation-attack-wiki]: https://en.wikipedia.org/wiki/Correlation_attack
