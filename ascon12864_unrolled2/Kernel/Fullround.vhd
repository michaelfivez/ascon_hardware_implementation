-------------------------------------------------------------------------------
--! @project    Unrolled (2) hardware implementation of Asconv1286
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
		RoundNr : in std_logic_vector(2 downto 0);
		RoundOut0,RoundOut1,RoundOut2,RoundOut3,RoundOut4 : out std_logic_vector(63 downto 0));
end entity Fullrounds;

architecture structural of Fullrounds is
	signal RoundNr_0, RoundNr_1 : std_logic_vector(3 downto 0);
	signal SboxOut0_0,SboxOut0_1,SboxOut0_2,SboxOut0_3,SboxOut0_4 : std_logic_vector(63 downto 0);
	signal SboxOut1_0,SboxOut1_1,SboxOut1_2,SboxOut1_3,SboxOut1_4 : std_logic_vector(63 downto 0);
	signal DiffOut0_0,DiffOut0_1,DiffOut0_2,DiffOut0_3,DiffOut0_4 : std_logic_vector(63 downto 0);
begin
	-- declare and connect all sub entities
	sbox1: entity work.Sbox port map(Reg0Out,Reg1Out,Reg2Out,Reg3Out,Reg4Out,RoundNr_0,
		SboxOut0_0,SboxOut0_1,SboxOut0_2,SboxOut0_3,SboxOut0_4);
	difflayer1: entity work.FullDiffusionLayer port map(SboxOut0_0,SboxOut0_1,SboxOut0_2,SboxOut0_3,SboxOut0_4,
		DiffOut0_0,DiffOut0_1,DiffOut0_2,DiffOut0_3,DiffOut0_4);
	sbox2: entity work.Sbox port map(DiffOut0_0,DiffOut0_1,DiffOut0_2,DiffOut0_3,DiffOut0_4,RoundNr_1,
		SboxOut1_0,SboxOut1_1,SboxOut1_2,SboxOut1_3,SboxOut1_4);
	difflayer2: entity work.FullDiffusionLayer port map(SboxOut1_0,SboxOut1_1,SboxOut1_2,SboxOut1_3,SboxOut1_4,
		RoundOut0,RoundOut1,RoundOut2,RoundOut3,RoundOut4);	

	RoundNr_0 <= RoundNr & '0';	
	RoundNr_1 <= RoundNr & '1';	

end architecture structural;
