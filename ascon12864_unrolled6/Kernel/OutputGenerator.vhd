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

entity OutputGenerator is
	port(
		In0 : in std_logic_vector(63 downto 0);
		DataIn : in std_logic_vector(63 downto 0);
		Size : in std_logic_vector(2 downto 0);
		Activate : in std_logic;
		Out0 : out std_logic_vector(63 downto 0);
		DataOut : out std_logic_vector(63 downto 0));
end entity OutputGenerator;

architecture structural of OutputGenerator is
	constant ALLZERO : std_logic_vector(63 downto 0) := (others => '0');
	signal Temp0,Temp1,Temp2 : std_logic_vector(63 downto 0);
begin
	Gen: process(In0,DataIn,Size,Activate,Temp0,Temp1,Temp2) is
		-- Truncator0&1
		procedure doTruncate0 (			-- Truncate block 0 and 1 together
			signal Input : in std_logic_vector(63 downto 0);
			signal Size : in std_logic_vector(2 downto 0);
			signal Activate : in std_logic;
			signal Output : out std_logic_vector(63 downto 0)) is
			variable ActSize : std_logic_vector(3 downto 0);
		begin
			ActSize(3) := Activate;
			ActSize(2 downto 0) := Size;
			-- if inactive it lets everything trough, if active it lets the first blocksize bits trough
			logic: case ActSize is
				when "1001" => 
					Output(63 downto 56) <= Input(63 downto 56);
					Output(55) <= '1';
					Output(54 downto 0) <= ALLZERO(54 downto 0);
				when "1010" => 
					Output(63 downto 48) <= Input(63 downto 48);
					Output(47) <= '1';
					Output(46 downto 0) <= ALLZERO(46 downto 0);
				when "1011" => 
					Output(63 downto 40) <= Input(63 downto 40);
					Output(39) <= '1';
					Output(38 downto 0) <= ALLZERO(38 downto 0);
				when "1100" => 
					Output(63 downto 32) <= Input(63 downto 32);
					Output(31) <= '1';
					Output(30 downto 0) <= ALLZERO(30 downto 0);
				when "1101" => 
					Output(63 downto 24) <= Input(63 downto 24);
					Output(23) <= '1';
					Output(22 downto 0) <= ALLZERO(22 downto 0);
				when "1110" => 
					Output(63 downto 16) <= Input(63 downto 16);
					Output(15) <= '1';
					Output(14 downto 0) <= ALLZERO(14 downto 0);
				when "1111" => 
					Output(63 downto 8) <= Input(63 downto 8);
					Output(7) <= '1';
					Output(6 downto 0) <= ALLZERO(6 downto 0);
				when others =>			-- deactivate or blocksize max or invalid input (cas 0xxxx or 10000)
					Output <= Input;
			end case logic;
		end procedure doTruncate0;

		-- Truncator2
		procedure doTruncate2 (			-- Truncate block 0 and 1 together
			signal Input : in std_logic_vector(63 downto 0);
			signal Size : in std_logic_vector(2 downto 0);
			signal Activate : in std_logic;
			signal Output : out std_logic_vector(63 downto 0)) is
			variable ActSize : std_logic_vector(3 downto 0);
		begin
			ActSize(3) := Activate;
			ActSize(2 downto 0) := Size;
			-- if inactive it lets everything trough, if active it blocks the first blocksize bits
			logic: case ActSize is
				when "1000" =>
					Output <= ALLZERO;
				when "1001" => 
					Output(63 downto 56) <= ALLZERO(63 downto 56);
					Output(55 downto 0) <= Input(55 downto 0);
				when "1010" => 
					Output(63 downto 48) <= ALLZERO(63 downto 48);
					Output(47 downto 0) <= Input(47 downto 0);
				when "1011" => 
					Output(63 downto 40) <= ALLZERO(63 downto 40);
					Output(39 downto 0) <= Input(39 downto 0);
				when "1100" => 
					Output(63 downto 32) <= ALLZERO(63 downto 32);
					Output(31 downto 0) <= Input(31 downto 0);
				when "1101" => 
					Output(63 downto 24) <= ALLZERO(63 downto 24);
					Output(23 downto 0) <= Input(23 downto 0);
				when "1110" => 
					Output(63 downto 16) <= ALLZERO(63 downto 16);
					Output(15 downto 0) <= Input(15 downto 0);
				when "1111" => 
					Output(63 downto 8) <= ALLZERO(63 downto 8);
					Output(7 downto 0) <= Input(7 downto 0);
				when others =>			-- deactivate or blocksize max or invalid input (cas 0xxxx or 10000)
					Output <= Input;
			end case logic;
		end procedure doTruncate2;
	begin
		-- DataOut
		DataOut <= In0 xor DataIn;
		-- Stateupdate
		doTruncate0(DataIn,Size,Activate,Temp0);
		Temp1 <= In0;	
		doTruncate2(Temp1,Size,Activate,Temp2);
		Out0 <= Temp0 xor Temp2;
	end process Gen;
end architecture structural;
