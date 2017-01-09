-------------------------------------------------------------------------------
--! @project    Iterate hardware implementation of Asconv128128
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
use ieee.std_logic_1164.ALL;
use ieee.numeric_std.all;

entity CipherCore is
    generic (
        G_NPUB_SIZE              : integer := 128;   --! Npub size (bits)
        G_NSEC_SIZE              : integer := 128;   --! Nsec size (bits)
        G_DBLK_SIZE              : integer := 128;  --! Data Block size (bits)
        G_KEY_SIZE               : integer := 128;  --! Key size (bits)
        G_RDKEY_SIZE             : integer := 128;  --! Round Key size (bits)
        G_TAG_SIZE               : integer := 128;  --! Tag size (bits)
        G_BS_BYTES               : integer := 4;    --! The number of bits required to hold block size expressed in bytes = log2_ceil(max(G_ABLK_SIZE,G_DBLK_SIZE)/8)
        G_CTR_AD_SIZE            : integer := 64;   --! Maximum size for the counter that keeps track of authenticated data
        G_CTR_D_SIZE             : integer := 64    --! Maximum size for the counter that keeps track of data
    );
    port (
        clk                  : in  std_logic;
        rst                  : in  std_logic;

        npub                 : in  std_logic_vector(G_NPUB_SIZE             -1 downto 0);
        nsec                 : in  std_logic_vector(G_NSEC_SIZE             -1 downto 0);
        key                  : in  std_logic_vector(G_KEY_SIZE              -1 downto 0);
        rdkey                : in  std_logic_vector(G_RDKEY_SIZE            -1 downto 0);
        bdi                  : in  std_logic_vector(G_DBLK_SIZE             -1 downto 0);
        exp_tag              : in  std_logic_vector(G_TAG_SIZE              -1 downto 0);
        len_a                : in  std_logic_vector(G_CTR_AD_SIZE           -1 downto 0);
        len_d                : in  std_logic_vector(G_CTR_D_SIZE            -1 downto 0);

        key_ready            : in  std_logic;
        key_updated          : out std_logic;
        key_needs_update     : in  std_logic;
        rdkey_ready          : in  std_logic;
        rdkey_read           : out std_logic;
        npub_ready           : in  std_logic;
        npub_read            : out std_logic;        
        nsec_ready           : in  std_logic;
        nsec_read            : out std_logic;
        bdi_ready            : in  std_logic;
        bdi_proc             : in  std_logic;
        bdi_ad               : in  std_logic;
        bdi_nsec             : in  std_logic;
        bdi_pad              : in  std_logic;
        bdi_decrypt          : in  std_logic;
        bdi_eot              : in  std_logic;
        bdi_eoi              : in  std_logic;
        bdi_read             : out std_logic;
        bdi_size             : in  std_logic_vector(G_BS_BYTES              -1 downto 0);
        bdi_valid_bytes      : in  std_logic_vector(G_DBLK_SIZE/8           -1 downto 0);
        bdi_pad_loc          : in  std_logic_vector(G_DBLK_SIZE/8           -1 downto 0);
        bdi_nodata           : in  std_logic;
        exp_tag_ready        : in  std_logic;

        bdo_ready            : in  std_logic;
        bdo_write            : out std_logic;
        bdo                  : out std_logic_vector(G_DBLK_SIZE             -1 downto 0);
        bdo_size             : out std_logic_vector(G_BS_BYTES+1            -1 downto 0);
        bdo_nsec             : out std_logic;
        tag_ready            : in  std_logic;
        tag_write            : out std_logic;
        tag                  : out std_logic_vector(G_TAG_SIZE              -1 downto 0);
        msg_auth_done        : out std_logic;
        msg_auth_valid       : out std_logic
    );
end entity CipherCore;

architecture structure of CipherCore is
	-- Registers
	signal keyreg,npubreg : std_logic_vector(127 downto 0);
	-- Control signals AsconCore
	signal AsconStart : std_logic;
	signal AsconMode : std_logic_vector(3 downto 0);
	signal AsconBusy : std_logic;
	signal AsconSize : std_logic_vector(3 downto 0);
	signal AsconInput : std_logic_vector(127 downto 0);
	-- Internal Datapath signals
	signal AsconOutput : std_logic_vector(127 downto 0);
begin
	-- Morus_core entity
	AsconCore : entity work.Ascon_StateUpdate port map(clk,rst,AsconStart,AsconMode,AsconSize,npubreg,keyreg,AsconInput,AsconBusy,AsconOutput);
	----------------------------------------
	------ DataPath for CipherCore ---------
	----------------------------------------
	datapath: process(AsconOutput,exp_tag,bdi,AsconInput) is
	begin
		-- Connect signals to the MorusCore
		AsconInput <= bdi;
		tag <= AsconOutput;
		bdo <= AsconOutput;
		if AsconOutput = exp_tag then
			msg_auth_valid <= '1';
		else
			msg_auth_valid <= '0';
		end if;
	end process datapath;


	----------------------------------------
	------ ControlPath for CipherCore ------
	----------------------------------------
	fsm: process(clk, rst) is
		type state_type is (IDLE,INIT_1,INIT_2,PROCESSING,RUN_CIPHER_1,RUN_CIPHER_2,RUN_CIPHER_3,TAG_1,TAG_2);
		variable CurrState : state_type := IDLE;
		variable firstblock : std_logic;
		variable lastblock : std_logic_vector(1 downto 0);
		variable afterRunning : std_logic_vector(2 downto 0);
	begin
		if(clk = '1' and clk'event) then
			if rst = '1' then		-- synchornous reset
				key_updated <= '0';
				CurrState := IDLE;
				firstblock := '0';
				keyreg <= (others => '0');
				npubreg <= (others => '0');
				AsconMode <= (others => '0'); -- the mode is a register
				afterRunning := (others => '0');
			else
		-- registers above in reset are used
		-- Standard values of the control signals are zero	
		AsconStart <= '0';
		bdi_read <= '0';
		msg_auth_done <= '0';
		bdo_write <= '0';
		bdo_size <= "10000";
		tag_write <= '0';
		npub_read <= '0';
		AsconSize <= (others => '0');

		FsmLogic: case CurrState is
		when IDLE =>
--			if key_needs_update = '1' then 	-- Key needs updating
--				if key_ready = '1' then
--					key_updated <= '1';
--					keyreg <= key;
--					CurrState := IDLE;
--				else
--					CurrState := IDLE;
--				end if;
			if key_needs_update = '1' and key_ready = '1' then	-- Key needs updating
				key_updated <= '1';
				keyreg <= key;
				CurrState := IDLE;
			elsif bdi_proc = '1' and npub_ready = '1' then		-- start of processing
				CurrState := INIT_1;
				npubreg <= npub;
				npub_read <= '1';
				AsconMode <= "0010"; -- Mode: initialization
				AsconStart <= '1';
			else
				CurrState := IDLE;
			end if;
		when INIT_1 =>
			if AsconBusy = '1' then
				CurrState := INIT_2; -- to INIT_2
			else
				AsconStart <= '1';
				CurrState := INIT_1; -- to INIT_1
			end if;
		when INIT_2 =>
			if AsconBusy = '0' then
				CurrState := PROCESSING; -- to PROCESSING
				firstblock := '1';
				lastblock := "00";
			else
				CurrState := INIT_2; -- to INIT_2
			end if;	

		-- EVEN SIMPLIFY THIS AFTER YOU SEE IF WORKS
		when PROCESSING =>
			if lastblock(1) = '1' then 				-- Generate the Tag
				AsconMode <= "0001";
				AsconStart <= '1';
				CurrState := TAG_1;
			elsif bdi_ready = '1' then
				if firstblock = '1' and bdi_ad = '0' then 	-- No associative data (and return in function)
					-- SEP_CONST
					AsconMode <= "0011";
					AsconStart <= '1';
					CurrState := PROCESSING;
				elsif bdi_ad = '1' then
					if bdi_eot = '0' then					
						-- AD_PROCESS
						AsconMode <= "0000";
						AsconStart <= '1';
						afterRunning := "000";
						CurrState := RUN_CIPHER_1;
					elsif bdi_eoi = '0' then
						if bdi_size = "0000" then
							-- AD_PROCESS + case2 + SEP_CONST
							AsconMode <= "0000";
							AsconStart <= '1';
							afterRunning := "001";
							CurrState := RUN_CIPHER_1;
						else
							-- AD_PROCESS + SEP_CONST
							AsconMode <= "0000";
							AsconStart <= '1';
							afterRunning := "010";
							CurrState := RUN_CIPHER_1;
						end if;
					else
						if bdi_size = "0000" then
							-- AD_PROCESS + case2 + SEP_CONST + case1
							AsconMode <= "0000";
							AsconStart <= '1';
							afterRunning := "101";
							CurrState := RUN_CIPHER_1;
						else
							-- AD_PROCESS + SEP_CONST + case1
							AsconMode <= "0000";
							AsconStart <= '1';
							afterRunning := "110";
							CurrState := RUN_CIPHER_1;
						end if;
					end if;
				else
					if bdi_decrypt = '0' then
						if bdi_eot = '0' then
							-- ENCRYPT
							AsconMode <= "0110";
							AsconStart <= '1';
							afterRunning := "011";
							CurrState := RUN_CIPHER_1;
						elsif bdi_size = "0000" then
							-- ENCRYPT + case1
							AsconMode <= "0110";
							AsconStart <= '1';
							afterRunning := "100";
							CurrState := RUN_CIPHER_1;
						else
							-- LAST_BLOCK_ENCRYPT
							bdi_read <= '1';
							AsconMode <= "0111";
							AsconStart <= '1';
							afterRunning := "011";
							CurrState := RUN_CIPHER_2;
						end if;
					else
						if bdi_eot = '0' then
							-- DECRYPT
							AsconMode <= "0100";
							AsconStart <= '1';
							afterRunning := "011";
							CurrState := RUN_CIPHER_1;
						elsif bdi_size = "0000" then
							-- DECRYPT + case1
							AsconMode <= "0100";
							AsconStart <= '1';
							afterRunning := "100";
							CurrState := RUN_CIPHER_1;
						else
							-- LAST_BLOCK_DECRYPT	
							bdi_read <= '1';
							AsconMode <= "0101";
							AsconStart <= '1';
							AsconSize <= bdi_size;
							afterRunning := "011";
							CurrState := RUN_CIPHER_2;
						end if;
					end if;
				end if;
				-- check if tag after (eoi, with special case when no associative data: 
				-- This is needed, because if no associative data, it will do it's thing and then still the message block is 
				-- left to be processed
				if firstblock = '1' and bdi_ad = '0' then 			-- lastblock will be set next return in the function
					lastblock := "00";
				elsif bdi_eoi = '1' and bdi_decrypt = '0' then			-- the one after is tag encryption
					lastblock := "10";
				elsif bdi_eoi = '1' then					-- the one after is tag decryption
					lastblock := "11";
				end if;
				-- not firstblock anymore :
				firstblock := '0';
			end if;

		when RUN_CIPHER_1 =>
			if AsconBusy = '1' then
				CurrState := RUN_CIPHER_2;
				bdi_read <= '1';
			else
				AsconStart <= '1';
				CurrState := RUN_CIPHER_1;
			end if;		
		when RUN_CIPHER_3 =>
			if AsconBusy = '1' then
				CurrState := RUN_CIPHER_2;
			else
				AsconStart <= '1';
				CurrState := RUN_CIPHER_3;
			end if;	

		when RUN_CIPHER_2 =>
			if AsconBusy = '0' then
				-- logic here:
			-- a simple variable is used for the cases where after the cipher something special has to be done:
				-- activating authregister after associative data		= 1
				-- resetting of blocknumber after last associative data		= 2 (so also do 1's job)
				-- giving of output after encryption/decryption			= 3 for encryption, 4 for decryption
				-- activating checksum after decription of message		= 4
				-- special giving of output after padded encryption/decryption	= 5 and 6 (determines output_sel), also wait with bdi_read	
				AfterRunLogic: case afterRunning is			
				when "000" => -- return to IDLE
					CurrState := PROCESSING;				
				when "001" => -- case2 and sep_cont after
					AsconMode <= "1001";
					AsconStart <= '1';
					CurrState := RUN_CIPHER_3;
					afterRunning := "010";
				when "010" => -- SEPCONSTANT and return to IDLE
					AsconMode <= "0011";
					AsconStart <= '1';
					CurrState := PROCESSING;
				when "011" => -- GIVE OUTPUT and return to IDLE
					if bdo_ready = '1' then
						bdo_write <= '1';
						CurrState := PROCESSING;
					else
						CurrState := RUN_CIPHER_2;
					end if;
				when "100" => -- GIVE OUTPUT & case1 and return to IDLE
					if bdo_ready = '1' then
						bdo_write <= '1';
						CurrState := PROCESSING;
						AsconMode <= "1000";
						AsconStart <= '1';
					else
						CurrState := RUN_CIPHER_2;
					end if;		
				when "101" => -- case2 and case1 and sep_cont after
					AsconMode <= "1001";
					AsconStart <= '1';
					CurrState := RUN_CIPHER_3;
					afterRunning := "110";
				when "110" => -- case1 and sep_cont after
					AsconMode <= "1000";
					AsconStart <= '1';
					CurrState := RUN_CIPHER_2;
					afterRunning := "010";			
				when others =>
				end case AfterRunLogic;
			else
				CurrState := RUN_CIPHER_2;
			end if;			

		when TAG_1 =>
			if AsconBusy = '1' then
				CurrState := TAG_2;
			else
				AsconStart <= '1';
				CurrState := TAG_1;
			end if;			
		when TAG_2 =>
			if AsconBusy = '0' and lastblock(0) = '0' then	-- Generate Tag
				if tag_ready = '1' then
					tag_write <= '1';
					key_updated <= '0';
					CurrState := IDLE;
				else
					CurrState := TAG_2;
				end if;
			elsif AsconBusy = '0' then			-- Compare Tag
				if exp_tag_ready = '1' then
					msg_auth_done <= '1';
					key_updated <= '0';
					CurrState := IDLE;
				else
					CurrState := TAG_2;
				end if;
			else
				CurrState := TAG_2;
			end if;	
		when others =>
		end case FsmLogic;
		end if;
		end if;
	end process fsm;
end architecture structure;
