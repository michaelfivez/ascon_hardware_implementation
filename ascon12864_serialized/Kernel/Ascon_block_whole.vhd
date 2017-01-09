-------------------------------------------------------------------------------
--! @project    Serialized hardware implementation of Asconv1286
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

entity Ascon_StateUpdate is
	port(
		Clk : in std_logic;	-- Clock
		Reset : in std_logic;	-- Reset (synchronous)
		-- ExtInputs
		Start : in std_logic;
		Mode : in std_logic_vector(3 downto 0);
		Size : in std_logic_vector(2 downto 0); -- only matters for last block decryption
		IV : in std_logic_vector(127 downto 0);
		Key : in std_logic_vector(127 downto 0);
		DataIn : in std_logic_vector(63 downto 0);
		Busy : out std_logic;
		DataOut : out std_logic_vector(127 downto 0));
end entity Ascon_StateUpdate;

architecture structural of Ascon_StateUpdate is
	-- Control signals
	signal RoundNr : std_logic_vector(3 downto 0); -- biggest round is 12
	signal sel1,sel2,sel3,sel4 : std_logic_vector(1 downto 0);
	signal sel0 : std_logic_vector(2 downto 0);
	signal SelSbox : std_logic_vector(1 downto 0);
	signal SelDiff : std_logic_vector(2 downto 0);
	signal selout : std_logic;
	signal Reg0En,Reg1En,Reg2En,Reg3En,Reg4En,RegOutEn,SboxEnable : std_logic;
	signal ActivateGen : std_logic;
	signal GenSize : std_logic_vector(2 downto 0);
begin
	control: entity work.Ascon_StateUpdate_control port map (Clk, Reset, RoundNr, sel1, sel2, sel3, sel4, sel0, selout, SelSbox, SelDiff, Reg0En,
		Reg1En, Reg2En, Reg3En, Reg4En, RegOutEn, SboxEnable, ActivateGen, GenSize, Start, Mode, Size, Busy);

	datapath: entity work.Ascon_StateUpdate_datapath port map (Clk, Reset, RoundNr, sel1, sel2, sel3, sel4, sel0, selout, SelSbox, SelDiff, Reg0En,
		Reg1En, Reg2En, Reg3En, Reg4En, RegOutEn, SboxEnable, ActivateGen, GenSize, IV, Key, DataIn, DataOut);
end architecture structural;
