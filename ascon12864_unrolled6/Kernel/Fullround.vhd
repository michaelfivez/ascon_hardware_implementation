-------------------------------------------------------------------------------
--! @project    Unrolled (6) hardware implementation of Asconv1286
--! @author     Michael Fivez
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       This is an hardware implementation made for my graduation thesis
--!             at the KULeuven, in the COSIC department (year 2015-2016)
--!             The thesis is titled 'Energy efficient hardware implementations of CAESAR submissions',
--!             and can be found on the COSIC website (www.esat.kuleuven.be/cosic/publications)
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity Fullrounds is
	port(		
		Reg0Out,Reg1Out,Reg2Out,Reg3Out,Reg4Out : in std_logic_vector(63 downto 0);
		RoundNr : in std_logic;
		RoundOut0,RoundOut1,RoundOut2,RoundOut3,RoundOut4 : out std_logic_vector(63 downto 0));
end entity Fullrounds;

architecture structural of Fullrounds is
	signal RoundNr_0, RoundNr_1, RoundNr_2, RoundNr_3, RoundNr_4, RoundNr_5 : std_logic_vector(3 downto 0);
	signal SboxOut0_0,SboxOut0_1,SboxOut0_2,SboxOut0_3,SboxOut0_4 : std_logic_vector(63 downto 0);
	signal SboxOut1_0,SboxOut1_1,SboxOut1_2,SboxOut1_3,SboxOut1_4 : std_logic_vector(63 downto 0);
	signal SboxOut2_0,SboxOut2_1,SboxOut2_2,SboxOut2_3,SboxOut2_4 : std_logic_vector(63 downto 0);
	signal SboxOut3_0,SboxOut3_1,SboxOut3_2,SboxOut3_3,SboxOut3_4 : std_logic_vector(63 downto 0);
	signal SboxOut4_0,SboxOut4_1,SboxOut4_2,SboxOut4_3,SboxOut4_4 : std_logic_vector(63 downto 0);
	signal SboxOut5_0,SboxOut5_1,SboxOut5_2,SboxOut5_3,SboxOut5_4 : std_logic_vector(63 downto 0);
	signal DiffOut0_0,DiffOut0_1,DiffOut0_2,DiffOut0_3,DiffOut0_4 : std_logic_vector(63 downto 0);
	signal DiffOut1_0,DiffOut1_1,DiffOut1_2,DiffOut1_3,DiffOut1_4 : std_logic_vector(63 downto 0);
	signal DiffOut2_0,DiffOut2_1,DiffOut2_2,DiffOut2_3,DiffOut2_4 : std_logic_vector(63 downto 0);
	signal DiffOut3_0,DiffOut3_1,DiffOut3_2,DiffOut3_3,DiffOut3_4 : std_logic_vector(63 downto 0);
	signal DiffOut4_0,DiffOut4_1,DiffOut4_2,DiffOut4_3,DiffOut4_4 : std_logic_vector(63 downto 0);
begin
	-- declare and connect all sub entities
	sbox1: entity work.Sbox port map(Reg0Out,Reg1Out,Reg2Out,Reg3Out,Reg4Out,RoundNr_0,
		SboxOut0_0,SboxOut0_1,SboxOut0_2,SboxOut0_3,SboxOut0_4);
	difflayer1: entity work.FullDiffusionLayer port map(SboxOut0_0,SboxOut0_1,SboxOut0_2,SboxOut0_3,SboxOut0_4,
		DiffOut0_0,DiffOut0_1,DiffOut0_2,DiffOut0_3,DiffOut0_4);
	sbox2: entity work.Sbox port map(DiffOut0_0,DiffOut0_1,DiffOut0_2,DiffOut0_3,DiffOut0_4,RoundNr_1,
		SboxOut1_0,SboxOut1_1,SboxOut1_2,SboxOut1_3,SboxOut1_4);
	difflayer2: entity work.FullDiffusionLayer port map(SboxOut1_0,SboxOut1_1,SboxOut1_2,SboxOut1_3,SboxOut1_4,
		DiffOut1_0,DiffOut1_1,DiffOut1_2,DiffOut1_3,DiffOut1_4);	
	sbox3: entity work.Sbox port map(DiffOut1_0,DiffOut1_1,DiffOut1_2,DiffOut1_3,DiffOut1_4,RoundNr_2,
		SboxOut2_0,SboxOut2_1,SboxOut2_2,SboxOut2_3,SboxOut2_4);
	difflayer3: entity work.FullDiffusionLayer port map(SboxOut2_0,SboxOut2_1,SboxOut2_2,SboxOut2_3,SboxOut2_4,
		DiffOut2_0,DiffOut2_1,DiffOut2_2,DiffOut2_3,DiffOut2_4);	
	sbox4: entity work.Sbox port map(DiffOut2_0,DiffOut2_1,DiffOut2_2,DiffOut2_3,DiffOut2_4,RoundNr_3,
		SboxOut3_0,SboxOut3_1,SboxOut3_2,SboxOut3_3,SboxOut3_4);
	difflayer4: entity work.FullDiffusionLayer port map(SboxOut3_0,SboxOut3_1,SboxOut3_2,SboxOut3_3,SboxOut3_4,
		DiffOut3_0,DiffOut3_1,DiffOut3_2,DiffOut3_3,DiffOut3_4);	
	sbox5: entity work.Sbox port map(DiffOut3_0,DiffOut3_1,DiffOut3_2,DiffOut3_3,DiffOut3_4,RoundNr_4,
		SboxOut4_0,SboxOut4_1,SboxOut4_2,SboxOut4_3,SboxOut4_4);
	difflayer5: entity work.FullDiffusionLayer port map(SboxOut4_0,SboxOut4_1,SboxOut4_2,SboxOut4_3,SboxOut4_4,
		DiffOut4_0,DiffOut4_1,DiffOut4_2,DiffOut4_3,DiffOut4_4);	
	sbox6: entity work.Sbox port map(DiffOut4_0,DiffOut4_1,DiffOut4_2,DiffOut4_3,DiffOut4_4,RoundNr_5,
		SboxOut5_0,SboxOut5_1,SboxOut5_2,SboxOut5_3,SboxOut5_4);
	difflayer6: entity work.FullDiffusionLayer port map(SboxOut5_0,SboxOut5_1,SboxOut5_2,SboxOut5_3,SboxOut5_4,
		RoundOut0,RoundOut1,RoundOut2,RoundOut3,RoundOut4);	

	roundnrgen: process(RoundNr) is
	begin
		if RoundNr = '0' then
			RoundNr_0 <= "0000";	
			RoundNr_1 <= "0001";
			RoundNr_2 <= "0010";
			RoundNr_3 <= "0011";
			RoundNr_4 <= "0100";
			RoundNr_5 <= "0101";
		else
			RoundNr_0 <= "0110";	
			RoundNr_1 <= "0111";
			RoundNr_2 <= "1000";
			RoundNr_3 <= "1001";
			RoundNr_4 <= "1010";
			RoundNr_5 <= "1011";
		end if;
	end process;
end architecture structural;
