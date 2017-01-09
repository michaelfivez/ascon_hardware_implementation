-------------------------------------------------------------------------------
--! @file       bshift.vhd
--! @brief      Barrel shifter
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

library IEEE;
use IEEE.STD_LOGIC_1164.all;

entity bshift is
	generic (
		G_W 		: integer := 16;    --! Bit size (Must be divisible by 2)
        G_LOG2_W    : integer := 4;     --! LOG2(G_w)
		G_LEFT	 	: integer := 1;     --! Left shift enable (1 = left shift, 0 = right shift)
        G_ROTATE    : integer := 1;     --! Rotate enable     (1 = rotate, 0 = shift)
        G_SHIFT1    : integer := 0      --! Shift '1' instead of '0'. Applicable only for Shift operation.
	);
	port (
		ii   : in  std_logic_vector(G_W                 -1 downto 0);
		rtr  : in  std_logic_vector(G_LOG2_W            -1 downto 0);
		oo   : out std_logic_vector(G_W                 -1 downto 0) );
end bshift;

architecture struct of bshift is
    constant ZEROS                                  : std_logic_vector(G_W               -1 downto 0) := (others => '0');
    constant ONES                                   : std_logic_vector(G_W               -1 downto 0) := (others => '1');
	type temp_i_type is array (0 to G_LOG2_W) of      std_logic_vector(G_W               -1 downto 0);
	signal itemp                                    : temp_i_type;
begin
	itemp(0) <= ii;

    ROTATOR_GEN:
    if G_ROTATE = 1 generate
        LEFT_SHIFT_GEN:
        if G_LEFT = 1 generate
            barrel_gen : for k in 1 to G_LOG2_W generate
                itemp(k) <= itemp(k-1) when (rtr(k-1) = '0') else ( itemp(k-1)(G_W-(2**(k-1))-1 downto 0) & itemp(k-1)(G_W-1 downto G_W-(2**(k-1))));
            end generate;
        end generate;

        RIGHT_SHIFT_GEN:
        if G_LEFT = 0 generate
            barrel_gen : for k in 1 to G_LOG2_W generate
                itemp(k) <= itemp(k-1) when (rtr(k-1) = '0') else ( itemp(k-1)( (2**(k-1))-1 downto 0 )	& itemp(k-1)(G_W-1 downto 2**(k-1)));
            end generate;
        end generate;
    end generate;

    SHIFTER_GEN:
    if G_ROTATE = 0 generate
        LEFT_SHIFT_GEN:
        if G_LEFT = 1 generate
            SHIFT0_GEN:
            if G_SHIFT1 = 0 generate
                barrel_gen : for k in 1 to G_LOG2_W generate
                    itemp(k) <= itemp(k-1) when (rtr(k-1) = '0') else ( itemp(k-1)(G_W-(2**(k-1))-1 downto 0) & ZEROS(G_W-1 downto G_W-(2**(k-1))));
                end generate;
            end generate;
            SHIFT1_GEN:
            if G_SHIFT1 = 1 generate
                barrel_gen : for k in 1 to G_LOG2_W generate
                    itemp(k) <= itemp(k-1) when (rtr(k-1) = '0') else ( itemp(k-1)(G_W-(2**(k-1))-1 downto 0) &  ONES(G_W-1 downto G_W-(2**(k-1))));
                end generate;
            end generate;
        end generate;

        RIGHT_SHIFT_GEN:
        if G_LEFT = 0 generate
            SHIFT0_GEN:
            if G_SHIFT1 = 0 generate
                barrel_gen : for k in 1 to G_LOG2_W generate
                    itemp(k) <= itemp(k-1) when (rtr(k-1) = '0') else ( ZEROS( (2**(k-1))-1 downto 0 )	& itemp(k-1)(G_W-1 downto 2**(k-1)));
                end generate;
            end generate;
            SHIFT1_GEN:
            if G_SHIFT1 = 1 generate
                barrel_gen : for k in 1 to G_LOG2_W generate
                    itemp(k) <= itemp(k-1) when (rtr(k-1) = '0') else (  ONES( (2**(k-1))-1 downto 0 )	& itemp(k-1)(G_W-1 downto 2**(k-1)));
                end generate;
            end generate;
        end generate;
    end generate;


	oo <= itemp(G_LOG2_W);

end struct;
