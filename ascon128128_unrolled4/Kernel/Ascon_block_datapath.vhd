-------------------------------------------------------------------------------
--! @project    Unrolled (factor 4) hardware implementation of Asconv128128
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
		RoundNr : in std_logic_vector(1 downto 0);
		sel1,sel2,sel3,sel4 : in std_logic_vector(1 downto 0);
		sel0 : in std_logic_vector(2 downto 0);
		selout : in std_logic;
		Reg0En,Reg1En,Reg2En,Reg3En,Reg4En,RegOutEn : in std_logic;
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
	signal Reg0In,Reg1In,Reg2In,Reg3In,Reg4In : std_logic_vector(63 downto 0);
	signal Reg0Out,Reg1Out,Reg2Out,Reg3Out,Reg4Out : std_logic_vector(63 downto 0);
	signal RegOutIn,RegOutOut : std_logic_vector(127 downto 0); 	
	-- Internal signals on datapath
	signal SboxOut0,SboxOut1,SboxOut2,SboxOut3,SboxOut4 : std_logic_vector(63 downto 0);
	signal DiffOut0,DiffOut1,DiffOut2,DiffOut3,DiffOut4 : std_logic_vector(63 downto 0);
	signal XorReg01,XorReg02,XorReg11,XorReg12 : std_logic_vector(63 downto 0);
	signal XorReg2,XorReg31,XorReg32,XorReg4 : std_logic_vector(63 downto 0);
	signal OutSig0,OutSig1 : std_logic_vector(127 downto 0);
begin
	-- declare and connect all sub entities
	rounds: entity work.Fullrounds port map(Reg0Out,Reg1Out,Reg2Out,Reg3Out,Reg4Out,RoundNr,DiffOut0,DiffOut1,DiffOut2,DiffOut3,DiffOut4);
	outpgen: entity work.OutputGenerator port map(Reg0Out,Reg1Out,DataIn,GenSize,ActivateGen,XorReg01,XorReg11,OutSig0); -- ActivateGen is a bit that indicates decryption or not

	---------------------------------------------
	------ Combinatorial logic for a round ------
	---------------------------------------------
	datapath: process(IV,Key,DataIn,Reg0Out,Reg1Out,Reg2Out,Reg3Out,Reg4Out,RegOutOut, -- inputs blocks and registers
			SboxOut0,SboxOut1,SboxOut2,SboxOut3,SboxOut4,DiffOut0,DiffOut1,DiffOut2,DiffOut3,DiffOut4, -- internal signals
			XorReg01,XorReg02,XorReg11,XorReg12,XorReg2,XorReg31,XorReg32,XorReg4,OutSig0,OutSig1, -- internal signals
			RoundNr,sel0,sel1,sel2,sel3,sel4,ActivateGen,selout,GenSize) is -- control signals
	begin
		-- Set correct inputs in registers
		if sel0 = "000" then
			Reg0In <= DiffOut0;
		elsif sel0 = "001" then
			Reg0In <= EXTRAIV;
		elsif sel0 = "010" then
			Reg0In <= XorReg01;
		elsif sel0 = "011" then
			Reg0In <= XorReg02;
		else 
			Reg0In <= Reg0Out xor ADCONSTANT;
		end if;
		if sel1 = "00" then
			Reg1In <= DiffOut1;
		elsif sel1 = "01" then
			Reg1In <= Key(127 downto 64);
		elsif sel1 = "10" then
			Reg1In <= XorReg11;
		else
			Reg1In <= XorReg12;
		end if;
		if sel2 = "00" then
			Reg2In <= DiffOut2;
		elsif sel2 = "01" then
			Reg2In <= Key(63 downto 0);
		else
			Reg2In <= XorReg2;
		end if;
		if sel3 = "00" then
			Reg3In <= DiffOut3;
		elsif sel3 = "01" then
			Reg3In <= IV(127 downto 64);
		elsif sel3 = "10" then
			Reg3In <= XorReg31; 
		else 
			Reg3In <= XorReg32;
		end if;
		if sel4 = "00" then
			Reg4In <= DiffOut4;
		elsif sel4 = "01" then
			Reg4In <= IV(63 downto 0);
		elsif sel4 = "10" then
			Reg4In <= XorReg4; 
		else
			Reg4In <= Reg4Out xor SEPCONSTANT;
		end if;
		XorReg02 <= Reg0Out xor Key(127 downto 64);
		XorReg12 <= Reg1Out xor Key(63 downto 0);
		XorReg2 <= Reg2Out xor Key(127 downto 64);
		XorReg31 <= Reg3Out xor Key(127 downto 64);
		XorReg32 <= Reg3Out xor Key(63 downto 0);
		XorReg4 <= Reg4Out xor Key(63 downto 0);
		-- Set output
		OutSig1(127 downto 64) <= XorReg31;
		OutSig1(63 downto 0) <= XorReg4;		
		if selout = '0' then
			RegOutIn <= OutSig0;
		else
			RegOutIn <= OutSig1;
		end if;
		DataOut <= RegOutOut;
	end process datapath;

	---------------------------------------------
	------ The registers in the datapath --------
	---------------------------------------------
	registerdatapath : process(Clk,Reset) is
	begin
		if(Clk = '1' and Clk'event) then
			if Reset = '1' then		-- synchronous reset
				Reg0Out <= (others => '0');
				Reg1Out <= (others => '0');
				Reg2Out <= (others => '0');
				Reg3Out <= (others => '0');
				Reg4Out <= (others => '0');
				RegOutOut <= (others => '0');
			else
				-- update registers with enable
				if Reg0En = '1' then 
					Reg0Out <= Reg0In;
				end if;
				if Reg1En = '1' then 
					Reg1Out <= Reg1In;
				end if;
				if Reg2En = '1' then 
					Reg2Out <= Reg2In;
				end if;
				if Reg3En = '1' then 
					Reg3Out <= Reg3In;
				end if;
				if Reg4En = '1' then 
					Reg4Out <= Reg4In;
				end if;
				if RegOutEn = '1' then 
					RegOutOut <= RegOutIn;
				end if;
			end if;
		end if;
	end process registerdatapath;
end architecture structural;
