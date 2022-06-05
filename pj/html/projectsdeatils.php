<!DOCTYPE html>
<html lang="en">

<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">

	<!-- Boxicons -->
	<link href='https://unpkg.com/boxicons@2.0.9/css/boxicons.min.css' rel='stylesheet'>
	<!-- My CSS -->
	<link rel="stylesheet" href="../css/style.css">

	<link rel="team.html" href="team.html">
	<script src="index.html"></script>

	<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.1/dist/css/bootstrap.min.css">



	<title>Track</title>
	<include class="team html"></include>
</head>

<body>



	<!-- SIDEBAR -->
	<section id="sidebar">
		<a href="#" class="brand">
			<i class='bx bxs-smile'></i>
			<span class="text">Track</span>
		</a>
		<ul class="side-menu top">
			<li class="active">
				<a href="#">
					<i class='bx bxs-dashboard'></i>
					<span class="text">Dashboard</span>
				</a>
			</li>
			<li>
				<a href="./project2.php">
					<i class='bx bxs-shopping-bag-alt'></i>
					<span class="text"> Projects</span>
				</a>
			</li>
			<li>
				<a href="../html/projectsdeatils.php">
					<i class='bx bxs-doughnut-chart'></i>
					<span class="text">Analytics</span>
				</a>
			</li>
			<li>
				<a href="#">
					<i class='bx bxs-message-dots'></i>
					<span class="text">Updates</span>
				</a>
			</li>



			<br>


		</ul>
		<ul class="side-menu">
			<li>
				<a href="../setting/dashboard-master/index.html">
					<i class='bx bxs-cog'></i>
					<span class="text">Settings</span>
				</a>
			</li>
			<li>
				<a href="../html/homepage.html" class="logout">
					<i class='bx bxs-log-out-circle'></i>
					<span class="text">Logout</span>
				</a>
			</li>
		</ul>
	</section>
	<!-- SIDEBAR -->





	<!-- CONTENT -->
	<section id="content">
		<!-- NAVBAR -->
		<nav>
			<i class='bx bx-menu'></i>
			<a href="#" class="nav-link">Categories</a>
			<form action="#">
				<div class="form-input">
					<input type="search" placeholder="Search...">
					<button type="submit" class="search-btn"><i class='bx bx-search'></i></button>
				</div>
			</form>
			<input type="checkbox" id="switch-mode" hidden>
			<label for="switch-mode" class="switch-mode"></label>
			<a href="#" class="notification">
				<i class='bx bxs-bell'></i>
				<span class="num">8</span>
			</a>
			<!--<a href="#" class="profile onclick="menuToggle();">">
				
				<img src="../image/tren-lg-2.jpg">-->

			<div class="action">
				<div class="profile" onclick="menuToggle();">
					<img src="../image/tren-lg-2.jpg" alt="">
				</div>


			</div>


			</a>
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
						<li><i class='bx bx-chevron-right'></i></li>
						<li>
							<a class="active" href="#">Home</a>
						</li>
					</ul>
				</div>

			</div>
			<form method="post" enctype="multipart/form-data">
				<?php include('process.php'); ?>

				<div class="row col-md-12">

					<div class="form-group col-md-6">
						<label for="first_name">Site ID</label>
						<input type="text" class="form-control" id="Site ID" name="siteid" placeholder="Site ID">
					</div>
					<div class="form-group col-md-6">
						<label for="date">Date </label>
						<input type="date" class="form-control" id="date" name="date" placeholder="date">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">Site Name</label>
						<input type="text" class="form-control" id="Site Name" name="sitename" placeholder="Site Name">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">Site GPS</label>
						<input type="text" class="form-control" id="Site GPS" name="sitegps" placeholder="Site GPS">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">Carrier Name</label>
						<input type="text" class="form-control" id="Carrier Name" name="carriername" placeholder="Carrier Name">
					</div>

					<div class="form-group col-md-6">
						<label for="last_name">Tower height</label>
						<input type="text" class="form-control" id="Tower height" name="towerheight" placeholder="Tower height">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">Sector</label>
						<input type="text" class="form-control" id="Sector" name="sector" placeholder="Sector">
					</div>
					
					<div class="row form-group col-md-6 ">
						<label for="dropdown">Type of Scoop</label>
						<select name="typeofscoop" id="typeofscoop" class="form-control" required>
							<option value="">Select Scoop</option>
							<option value="1">Swap</option>
							<option value="2">cut over</option>
							<option value="3">Installation</option>
							<option value="4">Allignment</option>
							<option value="5">Other</option>
						</select>
					</div>

				</div>

				<div class="form-outline">

					<label class="form-label" for="Message">Message</label>
					<textarea class="form-control" id="Message" rows="8" name="message" placeholder="Message"></textarea>
					<br>

				</div>
				<div class="row col-md-12">

					<div class="form-group col-md-6">
						<label for="first_name">JHA</label>
						<input type="file" class="form-control" id="Site ID" name="job[]" placeholder="JHA">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">BARRICADING</label>
						<input type="file" class="form-control" id="barricading" name="barricading" placeholder="barricadingName">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">First Aid Box</label>
						<input type="file" class="form-control" id="firstaidbox" name="firstaidbox" placeholder="firstaidbox">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">Fire Extinguisher</label>
						<input type="file" class="form-control" id="fireextinguisher" name="fireextinguisher" placeholder="fireextinguisher">
					</div>

					<div class="form-group col-md-6">
						<label for="last_name">Tool Box</label>
						<input type="file" class="form-control" id="toolbox" name="toolbox" placeholder="toolbox">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">Rubbish Point</label>
						<input type="file" class="form-control" id="rubbishpoint" name="rubbishpoint" placeholder="rubbishpoint">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">Energizer</label>
						<input type="file" class="form-control" id="energizer" name="energizer" placeholder="energizer">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">Electric Fence</label>
						<input type="file" class="form-control" id="electricfence" name="electricfence" placeholder="electricfence">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">Grounding tower</label>
						<input type="file" class="form-control" id="Sector" name="groundingtower" placeholder="Sector">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">Central site</label>
						<input type="file" class="form-control" id="centralsite" name="centralsite" placeholder="centralsite">
					</div>
					<div class="form-group col-md-6">
						<label for="last_name">Team members</label>
						<input type="file" class="form-control" id="teammembers" name="teammembers" placeholder="teammembers">
					</div>

				</div>
				<div class=" form-group text-center">
					<button type="submit" name="addrecord" class="btn btn-primary btn-lg"> Add record</button>

				</div>
			</form>
		</main>
		<!-- MAIN -->
	</section>
	<!-- CONTENT -->


	<script src="../js/script.js"></script>
</body>

</html>