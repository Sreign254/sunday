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
					<i class='bx bxs-dashboard' ></i>
					<span class="text">Dashboard</span>
				</a>
			</li>
			<li>
				<a href="./project2.php">
					<i class='bx bxs-shopping-bag-alt' ></i>
					<span class="text"> Projects</span>
				</a>
			</li>
			<li>
				<a href="../html/projectsdeatils.php">
					<i class='bx bxs-doughnut-chart' ></i>
					<span class="text">Analytics</span>
				</a>
			</li>
			<li>
				<a href="#">
					<i class='bx bxs-message-dots' ></i>
					<span class="text">Updates</span>
				</a>
			</li>
		
			
			
			<br>
			
		
		</ul>
		<ul class="side-menu">
			<li>
				<a href="../setting/dashboard-master/index.html">
					<i class='bx bxs-cog' ></i>
					<span class="text">Settings</span>
				</a>
			</li>
			<li>
				<a href="../html/homepage.html" class="logout">
					<i class='bx bxs-log-out-circle' ></i>
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
			<i class='bx bx-menu' ></i>
			<a href="#" class="nav-link">Categories</a>
			<form action="#">
				<div class="form-input">
					<input type="search" placeholder="Search...">
					<button type="submit" class="search-btn"><i class='bx bx-search' ></i></button>
				</div>
			</form>
			<input type="checkbox" id="switch-mode" hidden>
			<label for="switch-mode" class="switch-mode"></label>
			<a href="#" class="notification">
				<i class='bx bxs-bell' ></i>
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
		<main>
			<div class="head-title">
				<div class="left">
					<h1>Dashboard</h1>
					<ul class="breadcrumb">
						<li>
							<a href="#">Projects</a>
						</li>
						<li><i class='bx bx-chevron-right' ></i></li>
						<li>
							<a class="active" href="#">Home</a>
						</li>
					</ul>
				</div>
				<a href="#" class="btn-download">
					<i class='bx bxs-cloud-download' ></i>
					<span class="text">Upload PDF</span>
				</a>
			</div>

			
			
			<div class="table-data">
				<div class="order">
					<section class="attendance">
						<div class="attendance-list">
						  <h1>Project List</h1>
						  <?php
					require_once 'db.php';

					//get all packages
					$sqlpack = "SELECT id,siteid,sitename FROM project_details";
					$stmtpack = $conn->prepare($sqlpack);
					$stmtpack->execute();
					$resultpack = $stmtpack->get_result();
					?>
					<table>
						<thead>
							<tr>
								<th>Site Id</th>
								<th>Site Name</th>
								<th>details</th>
							</tr>
						</thead>
						<tbody>
						<?php
							while ($rowpack = $resultpack->fetch_assoc()) {
							$siteid = $rowpack['siteid'];
							$sitename = $rowpack['sitename'];
							$id = $rowpack['id'];
							?>
							<tr>
								<td>
								<?= $siteid; ?>
								</td>
								<td><?= $sitename; ?></td>
								<td><a class="details completed" href="preview.php?edit=<?=$id; ?>">View</span></td>
							</tr>
							<?php  } ?>

						</tbody>
					</table>
				
							<a href="download report"></a>
						  </table>
						  
		</main>
		<!-- MAIN -->
	</section>
	<!-- CONTENT -->
	<script src="../js/script.js"></script>

	<script src="/js/script.js"></script>
</body>
</html>