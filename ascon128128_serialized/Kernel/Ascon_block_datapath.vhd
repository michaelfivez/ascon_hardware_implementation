-------------------------------------------------------------------------------
--! @project    Serialized hardware implementation of Asconv128128
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

entity Ascon_StateUpdate_datapath is
	port(
		Clk : in std_logic;	-- Clock
		Reset : in std_logic;	-- Reset (synchronous)
		-- Control signals
		RoundNr : in std_logic_vector(3 downto 0); -- biggest round is 12
		sel1,sel2,sel3,sel4 : in std_logic_vector(1 downto 0);
		sel0 : in std_logic_vector(2 downto 0);
		selout : in std_logic;
		SelSbox : in std_logic_vector(1 downto 0);
		SelDiff : in std_logic_vector(2 downto 0);
		Reg0En,Reg1En,Reg2En,Reg3En,Reg4En,RegOutEn : in std_logic;
		SboxEnable : in std_logic;
		ActivateGen : in std_logic;
		GenSize : in std_logic_vector(3 downto 0);
		-- Data signals
		IV : in std_logic_vector(127 downto 0);
		Key : in std_logic_vector(127 downto 0);
		DataIn : in std_logic_vector(127 downto 0);
		DataOut : out std_logic_vector(127 downto 0)
	);
end entity Ascon_StateUpdate_datapath;

architecture structural of Ascon_StateUpdate_datapath is
	-- constants
	constant EXTRAIV : std_logic_vector(63 downto 0) := x"80800c0800000000"; -- used in the initialization
	constant SEPCONSTANT : std_logic_vector(63 downto 0) := x"0000000000000001";
	constant ADCONSTANT : std_logic_vector(63 downto 0) := x"8000000000000000";
	-- Register signals
	signal SboxReg0In,SboxReg1In,SboxReg2In,SboxReg3In,SboxReg4In : std_logic_vector(63 downto 0);
	signal SboxReg0Out,SboxReg1Out,SboxReg2Out,SboxReg3Out,SboxReg4Out : std_logic_vector(63 downto 0);
	signal DiffReg0Out,DiffReg1Out,DiffReg2Out,DiffReg3Out,DiffReg4Out : std_logic_vector(63 downto 0);
	signal RegOutIn,RegOutOut : std_logic_vector(127 downto 0); 	
	-- Internal signals on datapath
	signal Sbox0In,Sbox1In,Sbox2In,Sbox3In,Sbox4In : std_logic_vector(15 downto 0);
	signal Sbox0Out,Sbox1Out,Sbox2Out,Sbox3Out,Sbox4Out : std_logic_vector(15 downto 0);
	signal Diff1In, Diff2In, Diff3In, DiffOut : std_logic_vector(63 downto 0);
	signal XorReg01,XorReg02,XorReg11,XorReg12 : std_logic_vector(63 downto 0);
	signal XorReg2,XorReg31,XorReg32,XorReg4 : std_logic_vector(63 downto 0);
	signal OutSig0,OutSig1 : std_logic_vector(127 downto 0);
begin
	-- declare and connect all sub entities
	sboxregisters: entity work.Sbox_registers port map(Clk ,Sbox0Out, Sbox1Out, Sbox2Out, Sbox3Out, Sbox4Out, Sbox0In, Sbox1In, Sbox2In, Sbox3In, Sbox4In,
		SboxReg0In, SboxReg1In, SboxReg2In, SboxReg3In, SboxReg4In, SboxReg0Out, SboxReg1Out, SboxReg2Out, SboxReg3Out, SboxReg4Out,
		SelSbox, SboxEnable, Reg0En, Reg1En, Reg2En, Reg3En, Reg4En);

	sbox: entity work.Sbox port map(Sbox0In,Sbox1In,Sbox2In,Sbox3In,Sbox4In,RoundNr,Sbox0Out,Sbox1Out,Sbox2Out,Sbox3Out,Sbox4Out,SelSbox);
	difflayer: entity work.FullDiffusionLayer port map(Diff1In,Diff2In,Diff3In,DiffOut);
	outpgen: entity work.OutputGenerator port map(SboxReg0Out,SboxReg1Out,DataIn,GenSize,ActivateGen,XorReg01,XorReg11,OutSig0); -- ActivateGen is a bit that indicates decryption or not

	---------------------------------------------
	------ Combinatorial logic for a round ------
	---------------------------------------------
	datapath: process(Diff1In, Diff2In, Diff3In, DiffOut, SboxReg0In, SboxReg1In, SboxReg2In, SboxReg3In, SboxReg4In,
		OutSig0, OutSig1, XorReg01, XorReg02, XorReg11, XorReg12, XorReg2, XorReg31, XorReg32, XorReg4,
		SboxReg0Out, SboxReg1Out, SboxReg2Out, SboxReg3Out, SboxReg4Out, Key, IV, RegOutIn, RegOutOut, sel0, sel1, sel2, sel3, sel4,
		selout) is
	begin
		-- Set correct inputs in registers
		if sel0 = "000" then
			SboxReg0In <= DiffOut;
		elsif sel0 = "001" then
			SboxReg0In <= EXTRAIV;
		elsif sel0 = "010" then
			SboxReg0In <= XorReg01;
		elsif sel0 = "011" then
			SboxReg0In <= XorReg02;
		else 
			SboxReg0In <= SboxReg0Out xor ADCONSTANT;
		end if;
		if sel1 = "00" then
			SboxReg1In <= DiffOut;
		elsif sel1 = "01" then
			SboxReg1In <= Key(127 downto 64);
		elsif sel1 = "10" then
			SboxReg1In <= XorReg11;
		else
			SboxReg1In <= XorReg12;
		end if;
		if sel2 = "00" then
			SboxReg2In <= DiffOut;
		elsif sel2 = "01" then
			SboxReg2In <= Key(63 downto 0);
		else
			SboxReg2In <= XorReg2;
		end if;
		if sel3 = "00" then
			SboxReg3In <= DiffOut;
		elsif sel3 = "01" then
			SboxReg3In <= IV(127 downto 64);
		elsif sel3 = "10" then
			SboxReg3In <= XorReg31; 
		else 
			SboxReg3In <= XorReg32;
		end if;
		if sel4 = "00" then
			SboxReg4In <= DiffOut;
		elsif sel4 = "01" then
			SboxReg4In <= IV(63 downto 0);
		elsif sel4 = "10" then
			SboxReg4In <= XorReg4; 
		else
			SboxReg4In <= SboxReg4Out xor SEPCONSTANT;
		end if;
		XorReg02 <= SboxReg0Out xor Key(127 downto 64);
		XorReg12 <= SboxReg1Out xor Key(63 downto 0);
		XorReg2 <= SboxReg2Out xor Key(127 downto 64);
		XorReg31 <= SboxReg3Out xor Key(127 downto 64);
		XorReg32 <= SboxReg3Out xor Key(63 downto 0);
		XorReg4 <= SboxReg4Out xor Key(63 downto 0);
		-- Set output
		OutSig1(127 downto 64) <= XorReg31;
		OutSig1(63 downto 0) <= XorReg4;		
		if selout = '0' then
			RegOutIn <= OutSig0;
		else
			RegOutIn <= OutSig1;
		end if;
		DataOut <= RegOutOut;
		if SelDiff = "000" then
			Diff1In(63 downto 64 - 19) <= SboxReg0Out(19 - 1 downto 0);
			Diff1In(63 - 19 downto 0) <= SboxReg0Out(63 downto 19);
			Diff2In(63 downto 64 - 28) <= SboxReg0Out(28 - 1 downto 0);
			Diff2In(63 - 28 downto 0) <= SboxReg0Out(63 downto 28);	
			Diff3In <= SboxReg0Out;
		elsif SelDiff = "001" then
			Diff1In(63 downto 64 - 61) <= SboxReg1Out(61 - 1 downto 0);
			Diff1In(63 - 61 downto 0) <= SboxReg1Out(63 downto 61);
			Diff2In(63 downto 64 - 39) <= SboxReg1Out(39 - 1 downto 0);
			Diff2In(63 - 39 downto 0) <= SboxReg1Out(63 downto 39);	
			Diff3In <= SboxReg1Out;
		elsif SelDiff = "010" then
			Diff1In(63 downto 64 - 1) <= SboxReg2Out(1 - 1 downto 0);
			Diff1In(63 - 1 downto 0) <= SboxReg2Out(63 downto 1);
			Diff2In(63 downto 64 - 6) <= SboxReg2Out(6 - 1 downto 0);
			Diff2In(63 - 6 downto 0) <= SboxReg2Out(63 downto 6);	
			Diff3In <= SboxReg2Out;
		elsif SelDiff = "011" then
			Diff1In(63 downto 64 - 10) <= SboxReg3Out(10 - 1 downto 0);
			Diff1In(63 - 10 downto 0) <= SboxReg3Out(63 downto 10);
			Diff2In(63 downto 64 - 17) <= SboxReg3Out(17 - 1 downto 0);
			Diff2In(63 - 17 downto 0) <= SboxReg3Out(63 downto 17);	
			Diff3In <= SboxReg3Out;
		else
			Diff1In(63 downto 64 - 7) <= SboxReg4Out(7 - 1 downto 0);
			Diff1In(63 - 7 downto 0) <= SboxReg4Out(63 downto 7);
			Diff2In(63 downto 64 - 41) <= SboxReg4Out(41 - 1 downto 0);
			Diff2In(63 - 41 downto 0) <= SboxReg4Out(63 downto 41);	
			Diff3In <= SboxReg4Out;
		end if;
	end process datapath;

	---------------------------------------------
	------ The registers in the datapath --------
	---------------------------------------------
	registerdatapath : process(Clk,Reset) is
	begin
		if(Clk = '1' and Clk'event) then
			if Reset = '1' then		-- synchronous reset
				RegOutOut <= (others => '0');
			else
				if RegOutEn = '1' then 
					RegOutOut <= RegOutIn;
				end if;
			end if;
		end if;
	end process registerdatapath;
end architecture structural;
