<?php

$path = $_SERVER['DOCUMENT_ROOT'].'/AES';

require_once($path.'/Sbox.php');
require_once($path.'/key_aes.php');
require_once($path.'/aes_e_trace.php');
require_once($path.'/rounds_trace.php');

class aes_encrypt{

	// Plain text data of the user ...
	public $plain_data;

	// Plain text data converted to Hex
	protected $hex_data;

	/*
		128 Bit block of Hex data 
		converted into the Associative
		array 
	 */
	protected $hex_data_aes_block;

	/*
		AES has it's own way of writing the
		data in a Matrix form so this 
		variable will be having that data
	 */
	protected $hex_data_matrix;

	// Encrypted data....
	public $e_data;

	// Key object for AES
	public $aes_key_obj;

	// Table 2 multiplication for AES Mix Col.
	private $aes_table2;

	// Table 3 multiplication for AES Mix Col.
	private $aes_table3;	

	// Object for AES Trace
	public $aes_trace;
	public $rounds;

	public $first_node, $last_node;
	public $first_ip_block, $last_ip_block;

	function __construct(){
		$this->aes_key_obj = new key_aes();
		
		$this->aes_trace = new aes_e_trace();
		$this->rounds = new rounds_trace();

		$this->aes_table2 = array(
			0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
			0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
			0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
			0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
			0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
			0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
			0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
			0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
			0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
			0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
			0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
			0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
			0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
			0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
			0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
			0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
			);

		$this->aes_table3 = array(
			0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
			0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
			0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
			0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
			0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
			0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
			0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
			0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
			0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
			0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
			0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
			0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
			0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
			0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
			0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
			0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
			);
	}

	public function start_aes_encrypt($plain_data, $aes_key="", $aes_key_size=128, $debug=false){
		$cipher_text = "";

		/*
			Convert the data of plain-text data
			into Hex data to be used by AES
			for encryption
		 */
		$this->plain_data = $plain_data;

		$this->user_input_to_hex($plain_data);

		// Converts the Hex data to an AES Block size .... i.e 128 Bit block
		$this->convert_hex_to_aes_block();

		if($aes_key_size == 128)
			$total_round = 10;
		else if($aes_key_size == 192)
			$total_round = 12;
		else
			$total_round = 14;	

		// Key generation of AES
		if(strlen(trim($aes_key)) == 0)
			$this->aes_key_obj->get_aes_key($aes_key_size);
		else
			$this->aes_key_obj->set_aes_key_hex($aes_key_size, $aes_key);
		
		
		$this->first_ip_block = $this->last_ip_block = $this->aes_trace;
		
		/*
		Start the AES encryption process based on the 
		number of rounds.... and on every 128 Bit
		block of data....
		 */
		for ($input_round=0; $input_round < count($this->hex_data_aes_block); $input_round++) { 

			// Now convert each and every block to an AES Format block....	
			$this->hex_data_matrix = $this->convert_aes_block_to_aes_matrix($this->hex_data_aes_block[$input_round]);
			$input_block = "";

			// Write the Hex Block for tracing
			if($input_round == 0){
				$this->first_ip_block->aes_hex_input_block = $this->hex_data_matrix;
				$this->first_ip_block->next_input_block = new aes_e_trace;
				$this->last_ip_block = $this->first_ip_block->next_input_block;

				$this->first_ip_block->rounds = new rounds_trace;			
			}
			else{
				$this->last_ip_block->aes_hex_input_block = $this->hex_data_matrix;
				$this->last_ip_block->next_input_block = new aes_e_trace;
				$this->last_ip_block = $this->last_ip_block->next_input_block;

				$this->last_ip_block->rounds = new rounds_trace;
			}

			for ($round_ctr=0; $round_ctr <= $total_round; $round_ctr++) { 

				if($round_ctr == 0){
					$tmp_key = $this->aes_key_obj->fetch_roundKey($round_ctr);
					$round_key = $this->aes_key_obj->display_aes_key_matrix($tmp_key);

					$input_block = $this->add_round_key($this->hex_data_matrix, $round_key);
					
					if($input_round == 0){
						$this->first_ip_block->rounds->round_key = $round_key;
						$this->first_ip_block->rounds->add_round = $input_block;	

						$this->first_ip_block->next_round = null;
					}
					else{
						$this->last_ip_block->rounds = new rounds_trace;
						$this->last_ip_block->rounds->round_key = $round_key;
						$this->last_ip_block->rounds->add_round = $input_block;	

						$this->last_ip_block->next_round = null;	
					}	
					
				}
				else if($round_ctr != 10){
					
					$subsitute_bytes_op = $this->subsitute_bytes($input_block);
					$shift_row_op = $this->shift_rows($subsitute_bytes_op);
					$mix_col_op = $this->mix_columns($shift_row_op);
					
					$tmp_key = $this->aes_key_obj->fetch_roundKey($round_ctr);
					$round_key = $this->aes_key_obj->display_aes_key_matrix($tmp_key);					

					$input_block = $this->add_round_key($mix_col_op, $round_key);
					
					if($input_round == 0){
						
						$tmp['sub_bytes'] = $subsitute_bytes_op;
						$tmp['shift_rows'] = $shift_row_op;
						$tmp['mix_cols'] = $mix_col_op;
						$tmp['round_key'] = $round_key;
						$tmp['add_round'] = $input_block;

						$this->rounds_debug($this->first_ip_block->rounds, $tmp);
						// var_dump($this->first_ip_block->next_round);

					}
					else{

						$tmp['sub_bytes'] = $subsitute_bytes_op;
						$tmp['shift_rows'] = $shift_row_op;
						$tmp['mix_cols'] = $mix_col_op;
						$tmp['round_key'] = $round_key;
						$tmp['add_round'] = $input_block;

						$this->rounds_debug($this->last_ip_block->rounds, $tmp);	
					}
					
				}
				else{
					$subsitute_bytes_op = $this->subsitute_bytes($input_block);
					$shift_row_op = $this->shift_rows($subsitute_bytes_op);

					$tmp_key = $this->aes_key_obj->fetch_roundKey($round_ctr);				
					$round_key = $this->aes_key_obj->display_aes_key_matrix($tmp_key);

					$input_block = $this->add_round_key($shift_row_op, $round_key);	
					
					if($input_round == 0){

						$tmp['sub_bytes'] = $subsitute_bytes_op;
						$tmp['shift_rows'] = $shift_row_op;

						$tmp['round_key'] = $round_key;
						$tmp['add_round'] = $input_block;	

						$this->rounds_debug($this->first_ip_block->rounds, $tmp);	

					}
					else{
						$tmp['sub_bytes'] = $subsitute_bytes_op;
						$tmp['shift_rows'] = $shift_row_op;

						$tmp['round_key'] = $round_key;
						$tmp['add_round'] = $input_block;	

						$this->rounds_debug($this->last_ip_block->rounds, $tmp);		
					}
				}

				
			}

			$cipher_text = $input_block;
		}
		$this->last_ip_block->next_input_block = null;
		if(is_null($this->last_ip_block->next_input_block))
			$this->first_ip_block->cipher = $cipher_text;


	}

	public function rounds_debug(&$roundObj, $roundDetails){
		
		if($roundObj->next_round == null){
			$roundObj->next_round = new rounds_trace;
			if(isset($roundDetails['sub_bytes']))
				$roundObj->next_round->sub_bytes = $roundDetails['sub_bytes'];
			
			if(isset($roundDetails['shift_rows']))
				$roundObj->next_round->shift_rows = $roundDetails['shift_rows'];

			if(isset($roundDetails['mix_cols']))
				$roundObj->next_round->mix_cols = $roundDetails['mix_cols'];

			if(isset($roundDetails['add_round']))
				$roundObj->next_round->add_round = $roundDetails['add_round'];

			if(isset($roundDetails['round_key']))	
				$roundObj->next_round->round_key = $roundDetails['round_key'];

			$roundObj->next_round->next_round = null;

			return;
		}
		else{
			$this->rounds_debug($roundObj->next_round, $roundDetails);
		}
	}

	/**
	 * [user_input_to_hex Converts the Input data of the user into Hex....]
	 * @param  [String] $plain_data [User's input data]
	 * @return [Hex]             [Hex value for the input data]
	 */
	protected function user_input_to_hex($plain_data){
		if(strlen($plain_data) == 0){
			echo "Nothing is entered";
			exit;
		}

		$this->hex_data = '';
	    
	    for ($i=0; $i < strlen($plain_data); $i++)
	    	$this->hex_data .= dechex(ord($plain_data[$i]));

	}

	/**
	 * [convert_hex_to_aes_block It'll take the Hex converted data
	 * of the user and then copy it in a 128 Bit block data
	 * used by AES encryption algorithm.... because AES takes the
	 * input data in a 128 Bit block size only]
	 */
	protected function convert_hex_to_aes_block(){
		
		$arr_index=0;	
		for($j=0; $j<strlen($this->hex_data); $j++){

			if((($j % 32) == 0) && ($j!=0))
				$arr_index++;

			if(!isset($this->hex_data_aes_block[$arr_index]))
				$this->hex_data_aes_block[$arr_index] = "";

			$this->hex_data_aes_block[$arr_index] .= $this->hex_data[$j];
		}

		/*
			Now need to double-check if the last block is of 128 bit
			or not .... if not then need to pad it with 0's for now
			0 is fine but later on it must be changed for
			security reasons....
		 */
		$last_counter = count($this->hex_data_aes_block)-1;
		$last_block = end($this->hex_data_aes_block);
		if(strlen($last_block) != 32){
			for($m=0; $m<(32 - strlen($last_block)); $m++)
				$this->hex_data_aes_block[$last_counter] .= '0';
		}

		// Write the data to AES Tracing Object
		$this->aes_trace->aes_hex_input_block = $this->hex_data_aes_block;
		// var_dump($this->hex_data_aes_block);
	}

	/**
	 * [convert_aes_block_to_aes_matrix Need to convert the Hex value of the user
	 * back to a Matrix representation which is used by AES for 
	 * encryption process....]
	 */
	protected function convert_aes_block_to_aes_matrix($hex_data){

		$tmp_aes_block = str_split($hex_data, 2);
		$tmp;

		$col_ctr=0;
		for ($l=0; $l<16; $l+=4) { 
			$tmp[0][$col_ctr] = $tmp_aes_block[$l];
			$tmp[1][$col_ctr] = $tmp_aes_block[$l+1];
			$tmp[2][$col_ctr] = $tmp_aes_block[$l+2];
			$tmp[3][$col_ctr] = $tmp_aes_block[$l+3];
			$col_ctr++;
		}

		return $tmp;
	}

	protected function add_round_key($ip_data, $round_key){
		
		$round_key_op = "";	

		for($row=0; $row<4; $row++){
			$tmp1 = dechex(hexdec($ip_data[$row][0]) ^ hexdec($round_key[$row][0]));
			(strlen($tmp1) == 2 ? $round_key_op[$row][0] = $tmp1 : $round_key_op[$row][0] = '0'.$tmp1);

			$tmp2 = dechex(hexdec($ip_data[$row][1]) ^ hexdec($round_key[$row][1]));
			(strlen($tmp2) == 2 ? $round_key_op[$row][1] = $tmp2 : $round_key_op[$row][1] = '0'.$tmp2);

			$tmp3 = dechex(hexdec($ip_data[$row][2]) ^ hexdec($round_key[$row][2]));
			(strlen($tmp3) == 2 ? $round_key_op[$row][2] = $tmp3 : $round_key_op[$row][2] = '0'.$tmp3);

			$tmp4 = dechex(hexdec($ip_data[$row][3]) ^ hexdec($round_key[$row][3]));
			(strlen($tmp4) == 2 ? $round_key_op[$row][3] = $tmp4 : $round_key_op[$row][3] = '0'.$tmp4);
		}

		return $round_key_op;
	}

	protected function subsitute_bytes($sbox_key){

		$sBox_ref = new Sbox;
		$subsitute_bytes_op = "";
		$tmp_sKey = "";

		for($row=0; $row<4; $row++){
			
			for($col=0; $col<4; $col++){
				$tmp = str_split($sbox_key[$row][$col]);			
				$sBox_key_pos = ((hexdec($tmp[0])) *16) + hexdec($tmp[1]);
				$val = dechex($sBox_ref->get_sBox($sBox_key_pos));
				
				if(strlen($val) == 1)
					$tmp_sKey .= '0'.$val;
				else
					$tmp_sKey .= $val;

				$subsitute_bytes_op[$row][$col] = $tmp_sKey;

				$tmp_sKey = "";
			}
		}

		return $subsitute_bytes_op;
	}

	protected function shift_rows($ip_data){

		for($row=1; $row<4; $row++){			
			$tmp = $ip_data[$row][0];
			
			if($row == 1){				
				$ip_data[1][0] = $ip_data[1][1];
				$ip_data[1][1] = $ip_data[1][2];
				$ip_data[1][2] = $ip_data[1][3];
				$ip_data[1][3] = $tmp;
			}
			else if($row == 2){
				$ip_data[2][0] = $ip_data[2][2];
				$tmp1 = $ip_data[2][1];
				$ip_data[2][1] = $ip_data[2][3];
				$ip_data[2][2] = $tmp;
				$ip_data[2][3] = $tmp1;	
			}
			else if($row == 3){
				$ip_data[3][0] = $ip_data[3][3];
				$tmp1 = $ip_data[3][1];
				$ip_data[3][1] = $tmp;
				$tmp2 = $ip_data[3][2];
				$ip_data[3][2] = $tmp1;
				$ip_data[3][3] = $tmp2;		
			}
		}

		return $ip_data;
	}

	/**
	 * [mix_columns The mix-column part of the AES will happen
	 * here in this function.]
	 * @param  [array] $ip_data [The Matrix form of input data]
	 * @return [array]          [mixed column values]
	 */
	protected function mix_columns($ip_data){

		$mixed_col = array();

		for ($i=0; $i < 4; $i++) { 
			
			$ans1_tmp = ($this->aes_table2[hexdec($ip_data[0][$i])]);
			$ans2_tmp = ($this->aes_table3[hexdec($ip_data[1][$i])]);
			$ans3_tmp = hexdec($ip_data[2][$i]);
			$ans4_tmp = hexdec($ip_data[3][$i]);		
			$tmp_1_result = dechex($ans1_tmp ^ $ans2_tmp ^ $ans3_tmp ^ $ans4_tmp);
			$tmp_1_result = (strlen($tmp_1_result) == 1) ? '0'.$tmp_1_result : $tmp_1_result;
			
			$ans1_tmp = hexdec($ip_data[0][$i]);
			$ans2_tmp = ($this->aes_table2[hexdec($ip_data[1][$i])]);
			$ans3_tmp = ($this->aes_table3[hexdec($ip_data[2][$i])]);
			$ans4_tmp = hexdec($ip_data[3][$i]);
			$tmp_2_result = dechex($ans1_tmp ^ $ans2_tmp ^ $ans3_tmp ^ $ans4_tmp);
			$tmp_2_result = (strlen($tmp_2_result) == 1) ? '0'.$tmp_2_result : $tmp_2_result;
			
			$ans1_tmp = hexdec($ip_data[0][$i]);
			$ans2_tmp = hexdec($ip_data[1][$i]);
			$ans3_tmp = ($this->aes_table2[hexdec($ip_data[2][$i])]);
			$ans4_tmp = ($this->aes_table3[hexdec($ip_data[3][$i])]);
			$tmp_3_result = dechex($ans1_tmp ^ $ans2_tmp ^ $ans3_tmp ^ $ans4_tmp);
			$tmp_3_result = (strlen($tmp_3_result) == 1) ? '0'.$tmp_3_result : $tmp_3_result;
			
			$ans1_tmp = ($this->aes_table3[hexdec($ip_data[0][$i])]);
			$ans2_tmp = hexdec($ip_data[1][$i]);
			$ans3_tmp = hexdec($ip_data[2][$i]);
			$ans4_tmp = ($this->aes_table2[hexdec($ip_data[3][$i])]);
			$tmp_4_result = dechex($ans1_tmp ^ $ans2_tmp ^ $ans3_tmp ^ $ans4_tmp);
			$tmp_4_result = (strlen($tmp_4_result) == 1) ? '0'.$tmp_4_result : $tmp_4_result;
			
			$mixed_col[0][$i] = $tmp_1_result;
			$mixed_col[1][$i] = $tmp_2_result;
			$mixed_col[2][$i] = $tmp_3_result;
			$mixed_col[3][$i] = $tmp_4_result;
		}

		return $mixed_col;
	}

	/**
	 * [is_reduced This function will check if the given argument
	 * needs any reduction or not because the AES does operation 
	 * only in GF(2^8)]
	 * @param  [Int]  $dec_val [Dec formatted value]
	 * @return boolean          [Returns True if needed or False]
	 */
	protected function is_reduced($dec_val){
		$tmp = decbin($dec_val);
		
		/*
			If the value is greater than 8 
			in length then you need reduction
			not when it's 8 or less
		 */	
		if(strlen($tmp) > 8)
			return false;
		else 
			return true;
	}

	/**
	 * [poly_reduction This function will perform a polynomial
	 * reduction on the value by dividing the given input with 
	 * the given poly (x^8 + x^4 + x^3 + x + 1) whose dec value
	 * is 283]
	 * @param  [int] $ip_val [Dec value to be reduced]
	 * @return [int]         [Reduced dec value]
	 */
	public function poly_reduction($ip_val){
		// return ($ip_val % 283);
			
		$quotient = array();
		$remainder;
		$dividend2 = "";
			
		$dividend1_bin = decbin($ip_val);
		$dividend1_bin_len = strlen($dividend1_bin);

		$aes_poly = decbin(283);
		$aes_poly_len = strlen($aes_poly);

		$tmp = abs($dividend1_bin_len - $aes_poly_len);

		if($tmp == 0){
			array_push($quotient, 1);
			$dividend2 = $aes_poly;

			if(strlen(bindec($dividend2)) > $dividend1_bin_len){
				for ($i=0; $i < $tmp; $i++) 
					$dividend2 .= 0;
			}

			$remainder = decbin(bindec($dividend2) ^ bindec($dividend1_bin));
			return bindec($remainder);
		}
		else{
			
			$dividend2 = $aes_poly;
			$dividend2 = bindec($dividend2) << $tmp;
		
			$remainder = decbin($dividend2 ^ bindec($dividend1_bin));
			return bindec($remainder);
		}

	}
}
?>