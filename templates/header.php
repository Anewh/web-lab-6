<header class="header">
	<div class="header__container">
		<img class="logo" src="css/img/2.png">
		<form class="search-form">
  			<input type="search" class="search search-overwiew" placeholder="Search...">
		</form>

		<?php if (!isset($_SESSION['user_name'])): ?>
			<button class="header__nav__auth btn" id="sign-in" type="button"> Sign in </button>
 			<?php else: ?>
   			<p class="header__hello">Привет, <?= $_SESSION['user_name'] ?></p>
   			<button class="header__nav__auth btn" id="review" type="button"> Add review </button>
			<button class="header__nav__auth btn" id="logout" type="button"> Logout </button>
		<?php endif; ?>

		<div class="header__nav__menu">
			<!-- TODO -->
		</div>
	</div>
	<?php if (!isset($_SESSION['user_name'])) {
    require_once 'fragments/popup.php';
}?>
</header>