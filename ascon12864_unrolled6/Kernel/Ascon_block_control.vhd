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

entity Ascon_StateUpdate_control is
	port(
		Clk : in std_logic;	-- Clock
		Reset : in std_logic;	-- Reset (synchronous)
		-- Control signals
		RoundNr : out std_logic; -- biggest round is 12
		sel1,sel2,sel3,sel4 : out std_logic_vector(1 downto 0);
		sel0 : out std_logic_vector(2 downto 0);
		selout : out std_logic;
		Reg0En,Reg1En,Reg2En,Reg3En,Reg4En,RegOutEn : out std_logic;
		ActivateGen : out std_logic;
		GenSize : out std_logic_vector(2 downto 0);
		-- External control signals
		Start : in std_logic;
		Mode : in std_logic_vector(3 downto 0);
		Size : in std_logic_vector(2 downto 0); -- only matters for last block decryption
		Busy : out std_logic
	);
end entity Ascon_StateUpdate_control;

architecture structural of Ascon_StateUpdate_control is
begin
	-----------------------------------------
	------ The Finite state machine  --------
	-----------------------------------------
	-- Modes: initialization, associative data, encryption, decryption, tag generation, final encryption, final decryption, seperation constant
	-- 	 	0010		0000		0110	    0100	0001		0111			0101,		0011
	--	  case1 1000, case2 1001
	fsm: process(Clk, Reset) is
		type state_type is (IDLE,LOADNEW,CRYPT,TAG);
		variable CurrState : state_type := IDLE;
		variable RoundNrVar : std_logic_vector(1 downto 0);
	begin
		if Clk'event and Clk = '1' then
			-- default values
			sel0 <= "000";
			sel1 <= "00";
			sel2 <= "00";
			sel3 <= "00";
			sel4 <= "00";
			selout <= '0';
			Reg0En <= '0';
			Reg1En <= '0';
			Reg2En <= '0';
			Reg3En <= '0';
			Reg4En <= '0';
			RegOutEn <= '0';
			ActivateGen <= '0';
			GenSize <= "000";
			Busy <= '0';
			if Reset = '1' then -- synchronous reset active high
				-- registers used by fsm:
				RoundNrVar := "00";
				CurrState := IDLE;
			else
		FSMlogic : case CurrState is
		when IDLE =>
			if Start = '1' then
				Busy <= '1';
				if Mode = "0000" then 	-- AD mode
					RoundNrVar := "11"; -- so starts at 0 next cycle
					-- set Sel and Enables signal (Xor with DataIn)
					sel0 <= "010";
					Reg0En <= '1';
					CurrState := CRYPT;
				elsif Mode = "0100" then -- Decryption mode
					RoundNrVar := "11"; -- so starts at 0 next cycle
					-- set Sel and Enables signal (Generate output and xor state)
					ActivateGen <= '1';
					sel0 <= "010";
					Reg0En <= '1';
					RegOutEn <= '1';
					CurrState := CRYPT;
				elsif Mode = "0110" then -- Encryption 
					RoundNrVar := "11"; -- so starts at 0 next cycle
					-- set Sel and Enables signal (Generate output and xor state)
					sel0 <= "010";
					Reg0En <= '1';
					RegOutEn <= '1';
					CurrState := CRYPT;
				elsif Mode = "0001" then -- Tag mode
					RoundNrVar := "11"; -- so starts at 0 next cycle
					-- set Sel and Enables signal (XOR middle with key)
					sel1 <= "10";
					sel2 <= "11";
					Reg1En <= '1';
					Reg2En <= '1';
					CurrState := TAG;
				elsif Mode = "0111" then -- Last block encryption
					-- set Sel and Enables signal (Generate output and xor state)
					sel0 <= "010";
					Reg0En <= '1';
					RegOutEn <= '1';
					CurrState := IDLE;	
				elsif Mode = "0101" then -- Last block decryption
					-- set Sel and Enables signal (Generate output and xor state)
					ActivateGen <= '1';
					GenSize <= Size;
					sel0 <= "010";
					Reg0En <= '1';
					RegOutEn <= '1';					
					CurrState := IDLE;		
				elsif Mode = "0011" then -- Seperation constant	
					sel4 <= "11";
					Reg4En <= '1';
					CurrState := IDLE;	
				elsif Mode = "0010" then		-- Initialization mode
					RoundNrVar := "11"; -- so starts at 0 next cycle
					-- set Sel and Enables signal (Load in key and IV)
					sel0 <= "001";
					sel1 <= "01";
					sel2 <= "01";
					sel3 <= "01";
					sel4 <= "01";
					Reg0En <= '1';
					Reg1En <= '1';
					Reg2En <= '1';
					Reg3En <= '1';
					Reg4En <= '1';
					CurrState := LOADNEW;
				elsif Mode = "1000" then	-- case1
					sel0 <= "100";
					Reg0En <= '1';
					CurrState := IDLE;
				else				-- case2
					sel0 <= "100";
					Reg0En <= '1';
					RoundNrVar := "11"; -- so starts at 0 next cycle
					CurrState := CRYPT;
				end if;
			else
				Busy <= '0';
				CurrState := IDLE;		
			end if;
		when LOADNEW =>
			if RoundNrVar = "01" then -- first foesn't play a role, it's just to keep track in this if function
				-- set Sel and Enables signal (Xor at the end)
				sel3 <= "10";
				sel4 <= "10";
				Reg3En <= '1';
				Reg4En <= '1';	
				CurrState := IDLE;
				Busy <= '0';					
			else
				RoundNrVar := std_logic_vector(unsigned(RoundNrVar) + 1);
				-- set Sel and Enables signal (execute a round)
				Reg0En <= '1';
				Reg1En <= '1';
				Reg2En <= '1';
				Reg3En <= '1';
				Reg4En <= '1';				
				CurrState := LOADNEW;
				Busy <= '1';
			end if;									
		when CRYPT =>
				RoundNrVar := "00";
				Reg0En <= '1';
				Reg1En <= '1';
				Reg2En <= '1';
				Reg3En <= '1';
				Reg4En <= '1';		
				CurrState := IDLE;
				Busy <= '0';	
		when TAG =>
			if RoundNrVar = "01" then
				-- set Sel and Enables signal (connect tag to output)
				selout <= '1';
				RegOutEn <= '1';
				CurrState := IDLE;
				Busy <= '0';					
			else
				RoundNrVar := std_logic_vector(unsigned(RoundNrVar) + 1);
				-- set Sel and Enables signal (execute a round)
				Reg0En <= '1';
				Reg1En <= '1';
				Reg2En <= '1';
				Reg3En <= '1';
				Reg4En <= '1';				
				CurrState := TAG;
				Busy <= '1';
			end if;	
		end case FSMlogic;
		RoundNr <= RoundNrVar(0);
		end if;
		end if;
	end process fsm;
end architecture structural;
