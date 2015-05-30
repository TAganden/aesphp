<?php

if(!isset($_POST['aes-input']) || strlen($_POST['aes-input']) == 0){
	header('Location: index.html');
}

$path = $_SERVER['DOCUMENT_ROOT'].'/AES';

require_once($path."/aes_encrypt.php");
$aes_obj = new aes_encrypt();
$aes_obj->start_aes_encrypt($_POST['aes-input'], '', 128, true);
?>

<!-- Latest compiled and minified JavaScript -->
<script src="jquery.min.js"></script>

<!-- Latest compiled and minified CSS -->
<link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">

<!-- Optional theme -->
<link rel="stylesheet" href="bootstrap/css/bootstrap-theme.min.css">

<!-- Latest compiled and minified JavaScript -->
<script src="bootstrap/js/bootstrap.min.js"></script>


<link rel="stylesheet" href="jquery-ui.css">
<script src="jquery-ui.js"></script>


<style type="text/css">
	#og_msg{
		margin: 20px;
	}

	#block_badge{
		margin-left: 20px;
	}

	#tabs{
		margin: 20px;
	}

	.matrix {
	    position: relative;
	}
	.matrix:before, .matrix:after {
	    content: "";
	    position: absolute;
	    top: 0;
	    border: 1px solid #000;
	    width: 6px;
	    height: 100%;
	}
	.matrix:before {
	    left: -6px;
	    border-right: 0px;
	}
	.matrix:after {
	    right: -6px;
	    border-left: 0px;
	}
	.matrix td {
	    padding: 5px;    
	    text-align: center;
	}


</style>

<script>
  $(function() {
    $( "#tabs" ).tabs();
  });
  </script>

<div class="alert alert-info" id="og_msg" role="alert">Plain Text<br/><br/><b><?= $_POST['aes-input']; ?></b></div>

<div class="alert alert-info" id="og_msg" role="alert">Hex Message<br/><br/><b>
	<?php 
		for ($i=0; $i < 4; $i++){
			echo $aes_obj->aes_trace->aes_hex_input_block[0][$i].$aes_obj->aes_trace->aes_hex_input_block[1][$i].$aes_obj->aes_trace->aes_hex_input_block[2][$i].$aes_obj->aes_trace->aes_hex_input_block[3][$i]."\t";
		}
	?></b></div>

<div class="alert alert-success" id="og_msg" role="alert">Expanded <?= $aes_obj->aes_key_obj->aes_key_size; ?> bit cipher key<br/><br/><b>
	<?php 
		for ($i=0; $i < count($aes_obj->aes_key_obj->aes_key_expanded); $i++) { 
			if($i == 4)
				echo '<br/><br/>';
			// if($i%16 == 0)
			// 	echo '<br/>';

			echo $aes_obj->aes_key_obj->aes_key_expanded[$i]."\t";
		}
	?>
</b></div>

<div class="alert alert-success" id="og_msg" role="alert">Cipher Text<br/><br/><b>
	<?php
 		for ($i=0; $i < 4; $i++) { 
 			echo strtoupper($aes_obj->aes_trace->cipher[0][$i]).strtoupper($aes_obj->aes_trace->cipher[1][$i]).strtoupper($aes_obj->aes_trace->cipher[2][$i]).strtoupper($aes_obj->aes_trace->cipher[3][$i])."\t";
 		}
 	?></b></div>


<?php
$msg_ctr = 1;
$tmp_ip_block = $aes_obj->first_ip_block;
$tmp_round_node = $aes_obj->first_ip_block;

do{
?>
<!-- AES starts from here -->
<button class="btn btn-primary" id="block_badge" type="button">
  Message Block  <span class="badge"><?= $msg_ctr; ?></span>
</button>

<div class="alert alert-info" id="og_msg" role="alert">
	Hex Block<br/><br/>
	<b>
	<?php 
		for ($i=0; $i < 4; $i++){
			echo $tmp_ip_block->aes_hex_input_block[0][$i].$tmp_ip_block->aes_hex_input_block[1][$i].$tmp_ip_block->aes_hex_input_block[2][$i].$tmp_ip_block->aes_hex_input_block[3][$i]."\t";
		}
	?></b></div>

<div id="tabs">
	<ul>

  	<?php for ($i=0; $i <= 10; $i++):	 ?>		
		<li><a href="#tabs-<?= $i; ?>">Round <?= $i; ?></a></li>  
	<?php endfor; ?>

	</ul>

	<?php 
	
	for ($i=0; $i <= 10; $i++):	 
		if($i == 0)
			$tmp_round_node = $tmp_round_node->rounds;		
	?>			
  <div id="tabs-<?= $i; ?>">
  	<table class="table table-bordered" style="width:90%;">
  		<tr class="active">
  			<td style="padding-left:20px;">
  				Substitute Bytes
  			</td>

  			<td style="padding-left:20px;">
  				Shift Rows
  			</td>

  			<td style="padding-left:20px;">
  				Mix Columns
  			</td>

  			<td style="padding-left:20px;">
  				Add Round Keys
  			</td>

  			<td style="padding-left:20px;">
  				Key Schedule
  			</td>
  		</tr>
		<tr>
  			<td>
  				<table class="matrix" style="margin-left:20px;">
  					<?php if($i != 0): ?>
				    <tr>
				        <td><?= $tmp_round_node->sub_bytes[0][0]; ?></td>
				        <td><?= $tmp_round_node->sub_bytes[0][1]; ?></td>
				        <td><?= $tmp_round_node->sub_bytes[0][2]; ?></td>
				        <td><?= $tmp_round_node->sub_bytes[0][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->sub_bytes[1][0]; ?></td>
				        <td><?= $tmp_round_node->sub_bytes[1][1]; ?></td>
				        <td><?= $tmp_round_node->sub_bytes[1][2]; ?></td>
				        <td><?= $tmp_round_node->sub_bytes[1][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->sub_bytes[2][0]; ?></td>
				        <td><?= $tmp_round_node->sub_bytes[2][1]; ?></td>
				        <td><?= $tmp_round_node->sub_bytes[2][2]; ?></td>
				        <td><?= $tmp_round_node->sub_bytes[2][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->sub_bytes[3][0]; ?></td>
				        <td><?= $tmp_round_node->sub_bytes[3][1]; ?></td>
				        <td><?= $tmp_round_node->sub_bytes[3][2]; ?></td>
				        <td><?= $tmp_round_node->sub_bytes[3][3]; ?></td>
				    </tr>
				<?php else: ?>
					<tr>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				    </tr>
				    <tr>
				    	<td>00</td>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				    </tr>
				    <tr>
				    	<td>00</td>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				    </tr>
				    <tr>
				    	<td>00</td>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				    </tr>
				<?php endif; ?>
				</table>
  			</td>

  			<td>
  				<table class="matrix" style="margin-left:20px;">
				    <?php if($i != 0): ?>
				    <tr>
				        <td><?= $tmp_round_node->shift_rows[0][0]; ?></td>
				        <td><?= $tmp_round_node->shift_rows[0][1]; ?></td>
				        <td><?= $tmp_round_node->shift_rows[0][2]; ?></td>
				        <td><?= $tmp_round_node->shift_rows[0][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->shift_rows[1][0]; ?></td>
				        <td><?= $tmp_round_node->shift_rows[1][1]; ?></td>
				        <td><?= $tmp_round_node->shift_rows[1][2]; ?></td>
				        <td><?= $tmp_round_node->shift_rows[1][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->shift_rows[2][0]; ?></td>
				        <td><?= $tmp_round_node->shift_rows[2][1]; ?></td>
				        <td><?= $tmp_round_node->shift_rows[2][2]; ?></td>
				        <td><?= $tmp_round_node->shift_rows[2][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->shift_rows[3][0]; ?></td>
				        <td><?= $tmp_round_node->shift_rows[3][1]; ?></td>
				        <td><?= $tmp_round_node->shift_rows[3][2]; ?></td>
				        <td><?= $tmp_round_node->shift_rows[3][3]; ?></td>
				    </tr>
				<?php else: ?>
					<tr>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				    </tr>
				    <tr>
				    	<td>00</td>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				    </tr>
				    <tr>
				    	<td>00</td>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				    </tr>
				    <tr>
				    	<td>00</td>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				    </tr>
				<?php endif; ?>
				</table>
  			</td>

  			<td>
  				<table class="matrix" style="margin-left:20px;">
				    <?php if($i != 0 && $i != 10): ?>
				    <tr>
				        <td><?= $tmp_round_node->mix_cols[0][0]; ?></td>
				        <td><?= $tmp_round_node->mix_cols[0][1]; ?></td>
				        <td><?= $tmp_round_node->mix_cols[0][2]; ?></td>
				        <td><?= $tmp_round_node->mix_cols[0][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->mix_cols[1][0]; ?></td>
				        <td><?= $tmp_round_node->mix_cols[1][1]; ?></td>
				        <td><?= $tmp_round_node->mix_cols[1][2]; ?></td>
				        <td><?= $tmp_round_node->mix_cols[1][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->mix_cols[2][0]; ?></td>
				        <td><?= $tmp_round_node->mix_cols[2][1]; ?></td>
				        <td><?= $tmp_round_node->mix_cols[2][2]; ?></td>
				        <td><?= $tmp_round_node->mix_cols[2][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->mix_cols[3][0]; ?></td>
				        <td><?= $tmp_round_node->mix_cols[3][1]; ?></td>
				        <td><?= $tmp_round_node->mix_cols[3][2]; ?></td>
				        <td><?= $tmp_round_node->mix_cols[3][3]; ?></td>
				    </tr>
				<?php else: ?>
					<tr>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				    </tr>
				    <tr>
				    	<td>00</td>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				    </tr>
				    <tr>
				    	<td>00</td>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				    </tr>
				    <tr>
				    	<td>00</td>
				        <td>00</td>
				        <td>00</td>
				        <td>00</td>
				    </tr>
				<?php endif; ?>
				</table>
  			</td>

  			<td>
  				<table class="matrix" style="margin-left:20px;">
				    <?php if($i == 0): ?>
				    <tr>
				        <td><?= strtoupper($tmp_round_node->add_round[0][0]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[0][1]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[0][2]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[0][3]); ?></td>
				    </tr>
				    <tr>
				    	<td><?= strtoupper($tmp_round_node->add_round[1][0]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[1][1]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[1][2]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[1][3]); ?></td>
				    </tr>
				    <tr>
				    	<td><?= strtoupper($tmp_round_node->add_round[2][0]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[2][1]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[2][2]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[2][3]); ?></td>
				    </tr>
				    <tr>
				    	<td><?= strtoupper($tmp_round_node->add_round[3][0]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[3][1]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[3][2]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[3][3]); ?></td>
				    </tr>
					<?php else: ?>
					<tr>
				        <td><?= strtoupper($tmp_round_node->add_round[0][0]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[0][1]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[0][2]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[0][3]); ?></td>
				    </tr>
				    <tr>
				    	<td><?= strtoupper($tmp_round_node->add_round[1][0]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[1][1]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[1][2]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[1][3]); ?></td>
				    </tr>
				    <tr>
				    	<td><?= strtoupper($tmp_round_node->add_round[2][0]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[2][1]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[2][2]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[2][3]); ?></td>
				    </tr>
				    <tr>
				    	<td><?= strtoupper($tmp_round_node->add_round[3][0]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[3][1]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[3][2]); ?></td>
				        <td><?= strtoupper($tmp_round_node->add_round[3][3]); ?></td>
				    </tr>
				<?php endif; ?>
				</table>
  			</td>

  			<td>
  				<table class="matrix" style="margin-left:20px;">
				    <?php if($i == 0): ?>
				    <tr>
				        <td><?= $tmp_round_node->round_key[0][0]; ?></td>
				        <td><?= $tmp_round_node->round_key[0][1]; ?></td>
				        <td><?= $tmp_round_node->round_key[0][2]; ?></td>
				        <td><?= $tmp_round_node->round_key[0][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->round_key[1][0]; ?></td>
				        <td><?= $tmp_round_node->round_key[1][1]; ?></td>
				        <td><?= $tmp_round_node->round_key[1][2]; ?></td>
				        <td><?= $tmp_round_node->round_key[1][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->round_key[2][0]; ?></td>
				        <td><?= $tmp_round_node->round_key[2][1]; ?></td>
				        <td><?= $tmp_round_node->round_key[2][2]; ?></td>
				        <td><?= $tmp_round_node->round_key[2][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->round_key[3][0]; ?></td>
				        <td><?= $tmp_round_node->round_key[3][1]; ?></td>
				        <td><?= $tmp_round_node->round_key[3][2]; ?></td>
				        <td><?= $tmp_round_node->round_key[3][3]; ?></td>
				    </tr>
					<?php else: ?>
					<tr>
				        <td><?= $tmp_round_node->round_key[0][0]; ?></td>
				        <td><?= $tmp_round_node->round_key[0][1]; ?></td>
				        <td><?= $tmp_round_node->round_key[0][2]; ?></td>
				        <td><?= $tmp_round_node->round_key[0][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->round_key[1][0]; ?></td>
				        <td><?= $tmp_round_node->round_key[1][1]; ?></td>
				        <td><?= $tmp_round_node->round_key[1][2]; ?></td>
				        <td><?= $tmp_round_node->round_key[1][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->round_key[2][0]; ?></td>
				        <td><?= $tmp_round_node->round_key[2][1]; ?></td>
				        <td><?= $tmp_round_node->round_key[2][2]; ?></td>
				        <td><?= $tmp_round_node->round_key[2][3]; ?></td>
				    </tr>
				    <tr>
				    	<td><?= $tmp_round_node->round_key[3][0]; ?></td>
				        <td><?= $tmp_round_node->round_key[3][1]; ?></td>
				        <td><?= $tmp_round_node->round_key[3][2]; ?></td>
				        <td><?= $tmp_round_node->round_key[3][3]; ?></td>
				    </tr>
				<?php endif; ?>
				</table>
  			</td>
  		</tr>
  	</table>
  </div>
<?php 
	$tmp_round_node = $tmp_round_node->next_round;	
	endfor; ?>
</div>
	
<?php
	}while(($tmp_ip_block = $tmp_ip_block->next_input_block) !== null && strlen($tmp_ip_block = $tmp_ip_block->next_input_block) != 0);	
?>


