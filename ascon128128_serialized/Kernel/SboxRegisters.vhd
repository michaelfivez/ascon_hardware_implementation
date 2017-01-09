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

entity Sbox_registers is
	port(
		Clk : in std_logic;	-- Clock
		Shift0In : in std_logic_vector(15 downto 0);	
		Shift1In : in std_logic_vector(15 downto 0);	
		Shift2In : in std_logic_vector(15 downto 0);	
		Shift3In : in std_logic_vector(15 downto 0);	
		Shift4In : in std_logic_vector(15 downto 0);	
		Shift0Out : out std_logic_vector(15 downto 0);	
		Shift1Out : out std_logic_vector(15 downto 0);	
		Shift2Out : out std_logic_vector(15 downto 0);	
		Shift3Out : out std_logic_vector(15 downto 0);	
		Shift4Out : out std_logic_vector(15 downto 0);	
		load0in : in std_logic_vector(63 downto 0);	
		load1in : in std_logic_vector(63 downto 0);	
		load2in : in std_logic_vector(63 downto 0);	
		load3in : in std_logic_vector(63 downto 0);	
		load4in : in std_logic_vector(63 downto 0);	
		load0out : out std_logic_vector(63 downto 0);	
		load1out : out std_logic_vector(63 downto 0);	
		load2out : out std_logic_vector(63 downto 0);	
		load3out : out std_logic_vector(63 downto 0);	
		load4out : out std_logic_vector(63 downto 0);
		Sel : in std_logic_vector(1 downto 0);
		ShiftEnable : in std_logic;
		Reg0En : in std_logic;
		Reg1En : in std_logic;
		Reg2En : in std_logic;
		Reg3En : in std_logic;
		Reg4En : in std_logic
	);
end entity Sbox_registers;

architecture structural of Sbox_registers is
	signal Part0_0, Part0_1, Part0_2, Part0_3 : std_logic_vector(15 downto 0);
	signal Part1_0, Part1_1, Part1_2, Part1_3 : std_logic_vector(15 downto 0);
	signal Part2_0, Part2_1, Part2_2, Part2_3 : std_logic_vector(15 downto 0);
	signal Part3_0, Part3_1, Part3_2, Part3_3 : std_logic_vector(15 downto 0);
	signal Part4_0, Part4_1, Part4_2, Part4_3 : std_logic_vector(15 downto 0);
begin
	----------------------------------
	------ Combinatorial logic  ------
	----------------------------------
	datapath: process(Part0_0, Part0_1, Part0_2, Part0_3, Part1_0, Part1_1, Part1_2, Part1_3, Part2_0, Part2_1, Part2_2, Part2_3,
		Part3_0, Part3_1, Part3_2, Part3_3, Part4_0, Part4_1, Part4_2, Part4_3, Sel) is
	begin
		load0out <= Part0_0 & Part0_1 & Part0_2 & Part0_3;
		load1out <= Part1_0 & Part1_1 & Part1_2 & Part1_3;
		load2out <= Part2_0 & Part2_1 & Part2_2 & Part2_3;
		load3out <= Part3_0 & Part3_1 & Part3_2 & Part3_3;
		load4out <= Part4_0 & Part4_1 & Part4_2 & Part4_3;
		if Sel = "00" then
			Shift0Out <= Part0_0;
			Shift1Out <= Part1_0;
			Shift2Out <= Part2_0;
			Shift3Out <= Part3_0;
			Shift4Out <= Part4_0;
		elsif Sel = "01" then
			Shift0Out <= Part0_1;
			Shift1Out <= Part1_1;
			Shift2Out <= Part2_1;
			Shift3Out <= Part3_1;
			Shift4Out <= Part4_1;
		elsif Sel = "10" then
			Shift0Out <= Part0_2;
			Shift1Out <= Part1_2;
			Shift2Out <= Part2_2;
			Shift3Out <= Part3_2;
			Shift4Out <= Part4_2;
		else
			Shift0Out <= Part0_3;
			Shift1Out <= Part1_3;
			Shift2Out <= Part2_3;
			Shift3Out <= Part3_3;
			Shift4Out <= Part4_3;
		end if;
	end process datapath;


	---------------------------------------------
	------ The registers in the datapath --------
	---------------------------------------------
	registerdatapath : process(Clk) is
	begin
		if(Clk = '1' and Clk'event) then
			if ShiftEnable = '1' then
				if Sel = "00" then 
					Part0_0 <= Shift0In;
					Part1_0 <= Shift1In;
					Part2_0 <= Shift2In;
					Part3_0 <= Shift3In;
					Part4_0 <= Shift4In;
				elsif Sel = "01" then
					Part0_1 <= Shift0In;
					Part1_1 <= Shift1In;
					Part2_1 <= Shift2In;
					Part3_1 <= Shift3In;
					Part4_1 <= Shift4In;	
				elsif Sel = "10" then
					Part0_2 <= Shift0In;
					Part1_2 <= Shift1In;
					Part2_2 <= Shift2In;
					Part3_2 <= Shift3In;
					Part4_2 <= Shift4In;		
				elsif Sel = "11" then
					Part0_3 <= Shift0In;
					Part1_3 <= Shift1In;
					Part2_3 <= Shift2In;
					Part3_3 <= Shift3In;
					Part4_3 <= Shift4In;	
				end if;	
			else	
				if Reg0En = '1' then
					Part0_0 <= load0in(63 downto 48);
					Part0_1 <= load0in(47 downto 32);
					Part0_2 <= load0in(31 downto 16);
					Part0_3 <= load0in(15 downto 0);
				end if;
				if Reg1En = '1' then
					Part1_0 <= load1in(63 downto 48);
					Part1_1 <= load1in(47 downto 32);
					Part1_2 <= load1in(31 downto 16);
					Part1_3 <= load1in(15 downto 0);
				end if;
				if Reg2En = '1' then
					Part2_0 <= load2in(63 downto 48);
					Part2_1 <= load2in(47 downto 32);
					Part2_2 <= load2in(31 downto 16);
					Part2_3 <= load2in(15 downto 0);
				end if;
				if Reg3En = '1' then
					Part3_0 <= load3in(63 downto 48);
					Part3_1 <= load3in(47 downto 32);
					Part3_2 <= load3in(31 downto 16);
					Part3_3 <= load3in(15 downto 0);
				end if;
				if Reg4En = '1' then
					Part4_0 <= load4in(63 downto 48);
					Part4_1 <= load4in(47 downto 32);
					Part4_2 <= load4in(31 downto 16);
					Part4_3 <= load4in(15 downto 0);
				end if;
			end if;	
		end if;
	end process registerdatapath;
end architecture structural;
