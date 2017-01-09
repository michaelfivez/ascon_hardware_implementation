-------------------------------------------------------------------------------
--! @file       AEAD_pkg.vhd
--! @brief      Package used for authenticated encyryption
--! @project    CAESAR Candidate Evaluation
--! @author     Ekawat (ice) Homsirikamol
--! @copyright  Copyright (c) 2015 Cryptographic Engineering Research Group
--!             ECE Department, George Mason University Fairfax, VA, U.S.A.
--!             All rights Reserved.
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       This is publicly available encryption source code that falls
--!             under the License Exception TSU (Technology and software-
--!             —unrestricted)
-------------------------------------------------------------------------------


library ieee;
use ieee.std_logic_1164.all;

package AEAD_pkg is
    --! Opcde
	constant OP_ENC      :   std_logic_vector(4                  -1 downto 0) := "0000";    --! Encryption only operation
    constant OP_DEC      :   std_logic_vector(4                  -1 downto 0) := "0001";    --! Decryption only operation
    constant OP_AE_ENC   :   std_logic_vector(4                  -1 downto 0) := "0010";    --! Authenticated Encryption operation
    constant OP_AE_DEC   :   std_logic_vector(4                  -1 downto 0) := "0011";    --! Authenticated Decryption operation
    constant OP_LD_KEY   :   std_logic_vector(4                  -1 downto 0) := "0100";    --! Load Key        (Used by Secret Data Input)
    constant OP_LD_RKEY  :   std_logic_vector(4                  -1 downto 0) := "0101";    --! Load Round Key  (Used by Public Data Input)
    constant OP_ACT_KEY  :   std_logic_vector(4                  -1 downto 0) := "0111";    --! Activate Key    (Used by Public Data Input)
    
    
    constant OP_AE_PASS  :   std_logic_vector(4                  -1 downto 0) := "1110";    --! Authenticated Decryption Pass
    constant OP_AE_FAIL  :   std_logic_vector(4                  -1 downto 0) := "1111";    --! Authenticated Decryption Fail

    --! Opcode extension for multi-mode operations
    constant OP_MAC      :   std_logic_vector(4                  -1 downto 0) := "0110";    --! MAC operation
    constant OP_HASH     :   std_logic_vector(4                  -1 downto 0) := "0111";    --! Hash operation
    constant OP_PRNG     :   std_logic_vector(4                  -1 downto 0) := "1000";    --! PRNG operation

    --! Segment Type Encoding
    constant ST_INSTR    :   std_logic_vector(4                  -1 downto 0) := "0000";    --! Instruction type
    constant ST_INIT     :   std_logic_vector(4                  -1 downto 0) := "0000";    --! Initialization type    
    constant ST_NPUB     :   std_logic_vector(4                  -1 downto 0) := "0001";    --! NPUB Type
    constant ST_AD       :   std_logic_vector(4                  -1 downto 0) := "0010";    --! Authenticated Data  type
    constant ST_MESSAGE  :   std_logic_vector(4                  -1 downto 0) := "0011";    --! Message type
    constant ST_CIPHER   :   std_logic_vector(4                  -1 downto 0) := "0100";    --! Cipher type
    constant ST_TAG      :   std_logic_vector(4                  -1 downto 0) := "0101";    --! Tag type
    constant ST_KEY      :   std_logic_vector(4                  -1 downto 0) := "0110";    --! Key type
    constant ST_RDKEY    :   std_logic_vector(4                  -1 downto 0) := "0111";    --! Key type    
    constant ST_NSEC     :   std_logic_vector(4                  -1 downto 0) := "1000";    --! Secret message number type
    constant ST_NSEC_CIPH:   std_logic_vector(4                  -1 downto 0) := "1001";    --! Encrypted secret message number type
    constant ST_LEN      :   std_logic_vector(4                  -1 downto 0) := "1100";    --! Length type
    

    --! Length specifier 
    constant LEN_MSG_ID  : integer := 8;                                                    --! Length of message ID        
    constant LEN_KEY_ID  : integer := 8;                                                    --! Length of Key ID
    constant LEN_OPCODE  : integer := 4;                                                    --! Length of opcode
    constant LEN_SMT_HDR : integer := 4;                                                    --! Length of segment header
    
    --! Other    
    constant CTR_SIZE_LIM   : integer := 16;                                            --! Limit to the segment counter size    

    --! Functions
    function maximum(a, b: integer) return integer;                                         --! Get maximum
    function nway_or( x : std_logic_vector) return std_logic;                               --! Or all bits of an input
    function get_words(size: integer; iowidth:integer) return integer;                      --! Calculate the number of I/O words for a particular size
    function get_width(size: integer; iowidth: integer) return integer;                     --! Calculate the width of register (used when not divisible by I/O size, i.e. NPUB = 96 with I/O = 64-bit) 
    function get_cntr_width(iowidth: integer) return integer;                               --! Calculate the length of size register (used when I/O size < counter limit size)
    function log2_ceil (N: natural) return natural;                                         --! Log(2) ceil
    function isNotDivisible(xx: integer; yy: integer) return integer;                          --! Determine a whether a value is divisible
end AEAD_pkg;

package body AEAD_pkg is
    --! maximum
    function maximum(a, b: integer) return integer is
    begin
        if (a > b) then
            return a;
        else
            return b;
        end if;
    end function maximum;

    
    --! Or gate to all the input
    function nway_or( x : std_logic_vector) return std_logic is
        variable y : std_logic;
    begin
        y := x(0);
        for i in x'low+1 to x'high loop
            y := y or x(i);
        end loop;
        return y;
    end function nway_or;

    --! Calculate the number of words
    function get_words(size: integer; iowidth:integer) return integer is
    begin
        if (size mod iowidth) > 0 then
            return size/iowidth + 1;
        else
            return size/iowidth;
        end if;
    end function get_words;

    --! Calculate the expected width
    function get_width(size: integer; iowidth: integer) return integer is
    begin
        if (iowidth >= size) then
            return size;
        else
            return (size mod iowidth)+size;
        end if;
    end function get_width;

    --! Get the size of the public data
    function get_cntr_width(iowidth: integer) return integer is
    begin
        if iowidth-16 >= CTR_SIZE_LIM then
            return CTR_SIZE_LIM;
        else
            return iowidth-16;
        end if;
    end function get_cntr_width;

    --! Log of base 2
    function log2_ceil (N: natural) return natural is
	begin
		 if ( N = 0 ) then
			 return 0;
		 elsif N <= 2 then
			 return 1;
		 else
			if (N mod 2 = 0) then
				return 1 + log2_ceil(N/2);
			else
				return 1 + log2_ceil((N+1)/2);
			end if;
		 end if;
	end function log2_ceil;
    
    function isNotDivisible(xx: integer; yy: integer) return integer is
    begin
        if (xx MOD yy) /= 0 then
            return 1;
        else
            return 0;
        end if;
    end function isNotDivisible;
end package body AEAD_pkg;
