<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">

	<!-- Boxicons -->
	<link href='https://unpkg.com/boxicons@2.0.9/css/boxicons.min.css' rel='stylesheet'>
	<!-- My CSS -->
	
    

	
    
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.1/dist/css/bootstrap.min.css">



	<title>Track</title>
	<include class="team html"></include>
</head>
<body>
	


	<!-- SIDEBAR -->
	
	
	<!-- SIDEBAR -->

	



	<!-- CONTENT -->
	<section id="content">
		<!-- NAVBAR -->
		<nav>
			<i class='bx bx-menu' ></i>
			<a href="../html/main.php" class="nav-link">Back</a>
			
			<input type="checkbox" id="switch-mode" hidden>
			<label for="switch-mode" class="switch-mode"></label>
			
			<!--<a href="#" class="profile onclick="menuToggle();">">
				
				<img src="../image/tren-lg-2.jpg">-->

				
		
		</nav>
		<!-- NAVBAR -->

		<!-- MAIN -->
		<main class="bg-secondary">
			<div class="head-title">
				<div class="left">
					<h1>Project details</h1>
					<ul class="breadcrumb">
						<li>
							<a href="#">Project Details</a>
						</li>
						<li><i class='bx bx-chevron-right' ></i></li>
						<li>
							<a class="active" href="#">Home</a>
						</li>
					</ul>
				</div>

               
                <?php include('db.php'); ?>

    <?php 
    if (isset($_GET['edit'])) {
        $id = $_GET['edit'];
      
        $sql2 = "SELECT *
         FROM project_details WHERE id='$id'";
        $stmt2 = $conn->prepare($sql2);
        $stmt2->execute();
        $result2 = $stmt2->get_result();
        while ($row2 = $result2->fetch_assoc()) {
      
      
          $siteid = $row2['siteid'];
          $date= $row2['date'];
          $sitename = $row2['sitename'];
          $sitegps = $row2['sitegps'];
          $carriername = $row2['carriername'];
          $towerheight = $row2['towerheight'];
          $sector = $row2['sector'];
          $typeofscoop= $row2['typeofscoop'];
          $message = $row2['message'];
          $_filenamesjob = $row2['jha'];
          
        }
     
      }
    ?>

<form 
    id="survey-form" class="form-label">
    
        <div class="form-group">
            <label for="name" id="name-label"> Site ID</label>
            <input
              type="text"
              id=" site ID"
              class="form-control"
              placeholder="Enter  Site ID"
             
              value="<?= $siteid; ?>"
              disabled
            />
          </div>

          <div class="form-group">
            <label for="name" id="name-label"> Site Name</label>
            <input
              type="text"
              id=" Site Name"
              class="form-control"
             
              value="<?= $sitename; ?>"
              disabled
            />
          </div>
          
    
    
      <div class="form-group">
        <label for="GPS" id="GPS-label">Site GPS</label>
        <input
          type="Site GPS"
          id="Site GPS"
          class="form-control"
          placeholder="Enter your Site GPS"
          name="sitegps"
          value="<?= $sitegps; ?>"
          disabled
        />
      </div>

     

      <div class="form-group">
        <label for="dropdown"
          >Type of Scoop</label
        >
        <select 
         id="dropdown" 
         class="form-control"
         name="typeofscoop"
          disabled>
          <option>Select Scoop</option>
          <option value="Swap">Swap</option>
          <option value="cutover">cut over</option>
          <option value="Installation">Installation</option>
          
          <option value="Other">Other</option>
        </select>
      </div>

      <div class="form-group">
        <label for="dropdown"
          >Team Leader</label
        >
        <select  id="dropdown" 
        class="form-control" name="selectteamleader" disabled>
          <option>Select Team Leader</option>
          <option value="Jesse">Jesse</option>
          <option value="jackso">jackso</option>
          <option value="Mike">Mike</option>
          
          <option value="Other">Other</option>
        </select>
      </div>


      <div class="form-group">
        <p>Date of Scoop</p>
        <p>
          <label>
            <input
            
            type="date"
            id="date"
            class="form-control"
            placeholder="Enter scoop date"
            name="dateofscoop"
            value="<?= $sitedateofscoop; ?>"
            disabled
          />
          </label>
        </p>
        <p>
       
        
      
        </p>
        <p>
          <label>
            <input
              type="checkbox"
              name="additionalscoop"       
              value="<?= $additionalscoop; ?>"       
            />Additional Scoop
          </label>
        </p>
      </div>
      <div class="form-group">
        <p>Add Team Members here...</p>
        <textarea
          name="teammembers"
          value=""
          id="comment"
          cols="50"
          rows="6"
          placeholder="Add Team Members here..." 
          value="<?= $teammembers; ?>"   
          disabled
        ></textarea>
      </div>
      <div class="form-group">
          
      <img src="uploads/<?php echo $_filenamesjob;?>" class="rounded" alt="Cinque Terre" width="304" height="236"> 
      </div>

    </form>


		<!-- MAIN -->
	</section>
	<!-- CONTENT -->
	

	<script src="../js/script.js"></script>
</body>
</html>