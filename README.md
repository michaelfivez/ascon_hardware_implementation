# Description

This repository contains several implementations of the Ascon hardware cipher. Ascon is a candidate in the CAESAR competition (https://competitions.cr.yp.to/caesar.html). The implementations are made in the function of the graduation thesis of Michael Fivez (michael_fivez@hotmail.com) at the KULeuven, in the COSIC department (year 2015-2016).

The thesis is titled 'Energy efficient hardware implementations of CAESAR submissions', and can be found on the COSIC website (www.esat.kuleuven.be/cosic/publications).

A detailed description of the implementations can be found in this thesis.

# Contents

Each implementation has its own folder that contains the implementation in VHDL. It contains the API wrapper (see the thesis document for a description of this API), the cipher implementation, and some test vectors that verify its functionality (they are generated through software included in the above mentioned API).
