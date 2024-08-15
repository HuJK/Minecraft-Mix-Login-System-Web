<!--
  This is a demo page for AuthMe website integration.
  See AuthMeController.php and the extending classes for the PHP code you need.
-->
<!DOCTYPE html>

<html lang="en">
 <head>
   <title>AuthMe Integration Sample</title>
   <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
   <script type="text/javascript">
   let usernameJavaChangeTimeout;
   function hendleAutoFill(){
       const usernameJava = document.getElementsByName('username_java')[0];
       if ( usernameJava?.value?.length === 0){
           syncUsername();
       }
   }
   setTimeout(hendleAutoFill, 1500);
   function toggleUsernameFields() {
       const login_success = document.getElementById('login_success')?.value==="true";
       const last_login = JSON.parse(document.getElementById('last_login')?.value);
       const fastLogin = document.getElementById('fastlogin_checkbox');
       const usernameJava = document.getElementsByName('username_java')[0];
       const uuidJava = document.getElementsByName('uuid_java')[0];
       const uuidBedrock = document.getElementsByName('uuid_bedrock')[0];

       usernameJava.readOnly = true;
       usernameJava.style.backgroundColor='lightgray';
       uuidJava.readOnly = true;
       uuidJava.style.backgroundColor='lightgray';
        if(login_success && last_login !== null){
            uuidBedrock.disabled = !fastLogin.checked;
        } else {
            uuidBedrock.disabled = true;
            uuidBedrock.value = (fastLogin.checked?"Available after java login":"Not available");
        }
       //uuidBedrock.style.backgroundColor=(uuidBedrock.readOnly?'lightgray':'');
     }

     function syncUsername() {
       const username = document.getElementsByName('username')[0];
       const usernameJava = document.getElementsByName('username_java')[0];

       usernameJava.value = username.value;
       handleUsernameJavaChange();
     }
     function updateUuidJava() {
       const registerBtn = document.getElementById('register_btn');
       const usernameJava = document.getElementsByName('username_java')[0];
       const uuidJava = document.getElementsByName('uuid_java')[0];

       // Only make the API call if fastLogin is checked, login is not successful, and username_java is not empty
         const url = `https://corsproxy.io/?https://api.mojang.com/users/profiles/minecraft/${usernameJava.value}`;

         fetch(url)
           .then(response => {
             if (response.ok) {
               return response.json();
             } else {
               throw new Error('Failed to fetch UUID');
             }
           })
           .then(data => {
             uuidJava.value = data.id; // Update uuidJava with the fetched UUID
           })
           .catch(error => {
             console.error('Error:', error);
             uuidJava.value = ''; // Clear the UUID field if there is an error
           })
           .finally(() => {
             registerBtn.disabled=false;
             uuidJava.style.backgroundColor='lightgray';
           });

     }
     function handleUsernameJavaChange() {
      // Clear the previous timeout to ensure only the last change triggers the API call
      const login_success = document.getElementById('login_success')?.value==="true";
      const usernameJava = document.getElementsByName('username_java')[0];
      const registerBtn = document.getElementById('register_btn');
      if (!login_success && usernameJava.value !== ''){
       const uuidJava = document.getElementsByName('uuid_java')[0];
       if (document.getElementById('fastlogin_checkbox').checked) {
         clearTimeout(usernameJavaChangeTimeout);
         uuidJava.style.backgroundColor='gray';
         registerBtn.disabled=true;
         // Set a new timeout to delay the API call by 3 seconds
         usernameJavaChangeTimeout = setTimeout(updateUuidJava, 1500);
       }
       else{
         uuidJava.style.backgroundColor='lightgray';
         uuidJava.value='';
       }
      }
     }

     window.onload = function() {
       toggleUsernameFields(); // Set initial state based on checkbox

       // Add event listener for the Fast Login checkbox
       document.getElementById('fastlogin_checkbox').addEventListener('change', toggleUsernameFields);

       // Add event listener for the Username field
       document.getElementsByName('username')[0].addEventListener('input', syncUsername);

       // Add event listener for the Username(Java) field
       document.getElementsByName('username_java')[0].addEventListener('change', handleUsernameJavaChange);
       document.getElementById('fastlogin_checkbox').addEventListener('change', handleUsernameJavaChange);
     };
   </script>
 </head>
 <body>
<?php
error_reporting(E_ALL);

require 'AuthMeController.php';

// Change this to the file of the hash encryption you need, e.g. Bcrypt.php or Sha256.php
require 'Sha256.php';
// The class name must correspond to the file you have in require above! e.g. require 'Sha256.php'; and new Sha256();
$authme_controller = new Sha256();

$action = get_from_post_or_empty('action');
$user_orig = get_from_post_or_empty('username');
$user = strtolower($user_orig);
$user_java = get_from_post_or_empty('username_java');
$uuid_java = get_from_post_or_empty('uuid_java');
$uuid_bedrock = get_from_post_or_empty('uuid_bedrock');

if (strlen($uuid_java) === 0){
    $uuid_java = null;
} else if ( strlen($uuid_java) > 32 || ctype_xdigit($uuid_java) === false) {
    die(sprintf("Invalid uuid_java: %s<br>",$uuid_java));
} else {
    $uuid_java = str_pad($uuid_java, 32, "0", STR_PAD_LEFT);
    $uuid_java = strtolower($uuid_java);
}

if (strlen($uuid_bedrock) === 0 ) {
    $uuid_bedrock = null;
} else if ( strlen($uuid_bedrock) > 32 || ctype_xdigit($uuid_bedrock) === false) {
    die(sprintf("Invalid uuid_bedrock: %s<br>",$uuid_bedrock));
} else {
    $uuid_bedrock = ltrim($uuid_bedrock, '0');
    $uuid_bedrock = str_pad($uuid_bedrock, 16, "0", STR_PAD_LEFT);
    $uuid_bedrock = strtolower($uuid_bedrock);
}
$pass = get_from_post_or_empty('password');
$pass_new = get_from_post_or_empty('password_new');
$email = get_from_post_or_empty('email');
$invite = get_from_post_or_empty('invite');
$premium = (get_from_post_or_empty('premium') === "on") ? "1" : "0";
$login_success = false;
$userinfo = [];

$dont_print_table = false;
if ($action)
{
    if ($user === "")
    {
        echo '<h1>Error</h1> Empty username.';
        return;
    };
    if ($pass === "")
    {
        echo '<h1>Error</h1> Empty password.';
        return;
    }
    if ($action === 'Login')
    {
        $dont_print_table = process_login($user, $pass, $authme_controller);
    }
    else if ($action === 'Update')
    {
        $dont_print_table = process_update($user, $pass, $pass_new, $email, $premium, $user_java, $uuid_bedrock, $authme_controller);
    }
    else if ($action === 'Register')
    {
        $dont_print_table = process_register($user, $pass, $pass_new, $email, $invite, $premium, $user_java, $uuid_java, $uuid_bedrock, $authme_controller);
    }
}

if (!$dont_print_table)
{
    $fastlogin_click_html = '<tr><td><input type="checkbox" id="fastlogin_checkbox" name="premium" ' . ($premium === '1' ? 'checked' : "") . '>  </td><td> <label for="fastlogin_checkbox"> Mojang Login (I have a valid Mojang account), login without password confirmation and enable bedrock linking.</label><br> </td></tr>';

    echo '<h1>' . ($login_success ? "Login Success" : "AuthMe Login") . '</h1>
This is a demo form for AuthMe website integration.<br>
Login or Register in the following form.
<form method="post">
<input type="hidden" id="login_success" name="login_success" value="' . json_encode($login_success) . '">
<input type="hidden" id="last_login" name="last_login" value="' . json_encode(($login_success ? $userinfo["last_login"] : null)) . '">
<table>
   <tr><td>Userame</td><td><input type="text" value="' . htmlspecialchars($user_orig) . '" name="username" ' . ($login_success ? "readonly style=\"background-color: lightgrey;\" " : "") . '/></td></tr>
   <tr><td>Password</td><td><input type="password" value="' . htmlspecialchars($pass) . '" name="password" ' . ($login_success ? "readonly style=\"background-color: lightgrey;\" " : "") . '/></td></tr>';
    if (!$login_success)
    {
        echo '<tr><td>Confirm Password</td><td><input type="password" value="' . htmlspecialchars($pass_new) . '" name="password_new" /></td></tr>';
        echo '<tr><td>Invite Code</td><td><input type="text" value="' . htmlspecialchars($invite) . '" name="invite" ' . ($login_success ? "readonly  style=\"background-color: grey;\" " : "") . '/></td></tr>';
        echo $fastlogin_click_html;
    }
    echo '<tr>
     <td><input type="submit" name="action" value="Login" ' . ($login_success ? "disabled" : "") . '/></td>
     <td><input type="submit" name="action" value="Register" ' . ($login_success ? "disabled" : "") . ' id="register_btn"/></td>
   </tr>';
    echo '<tr><td>Username(Java)</td><td><input type="text" value="' . htmlspecialchars($user_java) . '" name="username_java" /></td></tr>';
    echo '<tr><td>UUID(Java)</td><td><input type="text" value="' . htmlspecialchars($uuid_java) . '" name="uuid_java" readonly/></td></tr>';
    $uuid_bedrock_message = "";
    if(!$login_success){
        $uuid_bedrock_message = "Available after java login";
    } else {
        $uuid_bedrock_message = $userinfo["uuid_bedrock"];
    }
    $get_uuid_bedrock_html='<button class="btn btn-success" onclick=" window.open(\'https://www.cxkes.me/xbox/xuid\',\'_blank\')"> Get XUID</button>';
    echo '<tr><td>XUID(Bedrock)</td><td><div style="display: flex; align-items: center;"><input type="text" value="' . $uuid_bedrock_message . '" name="uuid_bedrock" ' . ($login_success ? "" : "disabled") . '/>' . $get_uuid_bedrock_html . '</div></td></tr>';
    if ($login_success)
    {
        echo '<tr><td>New Password</td><td><input type="password" value="' . htmlspecialchars($pass_new) . '" name="password_new" /></td></tr>';
        echo $fastlogin_click_html;
    }
    echo '<tr>
     <td><input type="submit" name="action" value="Update" /></td>
   </tr>
 </table>
</form>';
}

//   <tr><td>Email</td><td><input type="text" value="' . htmlspecialchars($email) . '" name="email" /></td></tr>
//   <tr><td><input type="checkbox" id="fastlogin_checkbox" name="premium" value="1">  </td><td> <label for="fastlogin_checkbox"> Fast Login (I have a valid Mojang account)</label><br> </td></tr>
function get_from_post_or_empty($index_name)
{
    return trim(filter_input(INPUT_POST, $index_name, FILTER_UNSAFE_RAW, FILTER_REQUIRE_SCALAR | FILTER_FLAG_STRIP_LOW) ? : '');
}

// Login logic
function process_login($user, $pass, AuthMeController $controller)
{
    if ($controller->checkPassword($user, $pass))
    {
        global $userinfo;
        $userinfo = $controller->getUserInfo($user);
        if ($userinfo === null)
        {
            echo '<h1>Error</h1> userinfo not found.';
            return false;
        }
        #print_r($userinfo);
        global $login_success;
        global $user_java;
        global $uuid_java;
        global $uuid_bedrock;
        global $premium;
        global $email;
        $user = $user;
        $user_java = $userinfo['user_java'];
        $uuid_java = $userinfo['uuid_java'];
        $uuid_bedrock = $userinfo['uuid_bedrock'];
        $pass = $pass;
        $email = $userinfo['email'];
        $premium = ($userinfo['premium'] === "1") ? "1" : "0";
        $login_success = true;
        return false;
    }
    else
    {
        echo '<h1>Error</h1> Invalid username or password.';
        return true;
    }
    return false;
}

// Login logic
function process_update($user, $pass, $pass_new, $email, $premium, $user_java, $uuid_bedrock, AuthMeController $controller)
{
    if ($controller->checkPassword($user, $pass))
    {
        $userinfo = $controller->getUserInfo($user);
        if ($userinfo["isLogged"]===1){
            echo '<h1>Error</h1> Player is online. Please exit the game before update.';
            return true;
        }
        if ($pass_new !== "")
        {
            $controller->changePassword($user, $pass_new);
        }
        if ($email !== "")
        {
            $controller->changeEmail($user, $email);
        }
        if (!$controller->changePremium($user, $premium))
        {
            return true;
        }
        if (!$controller->changeUserJava($user, $user_java))
        {
            return true;
        }
        if (!$controller->changeBedrockXUID($user, $uuid_bedrock)) {
            return true;
        }
        printf('<h1>Hello, %s!</h1>', htmlspecialchars($user));
        echo 'Update successful. Nice to have you back!';
        if ($pass_new !== "")
        {
            echo '<br />New password = ********';
        }
        $userinfo = $controller->getUserInfo($user);
        echo '<br />Fast Login = ' . $userinfo['premium'];
        echo '<br />Username(Java) = ' . $userinfo['user_java'];
        echo '<br />UUID(Java) = ' . $userinfo['uuid_java'];
        echo '<br />XUID(Bedrock) = ' . $userinfo['uuid_bedrock'];
        echo '<br /><a href="index.php">Back to form</a>';
        return true;
    }
    else
    {
        echo '<h1>Error</h1> Invalid username or password.';
    }
    return false;
}

// Register logic
function process_register($user, $pass, $pass_new, $email, $invite, $premium, $user_java, $uuid_java, $uuid_bedrock, AuthMeController $controller)
{
    if ($controller->isUserRegistered($user,$user_java))
    {
        echo '<h1>Error</h1> This user already exists.';
    }
    else if (!is_email_valid($email))
    {
        echo '<h1>Error</h1> The supplied email is invalid.';
    }
    else if ($pass !== $pass_new)
    {
        echo '<h1>Error</h1> Password and confirm password does not match.';
    }
    else if (strlen($user_java) === 0)
    {
        echo '<h1>Error</h1> $user_java can\'t be empty.';
    }
    else
    {
        $ivstate = $controller->useInviteCode($invite);
        if ($ivstate != "OK")
        {
            if ($ivstate == "Already used")
            {
                echo '<h1>Error</h1> The supplied invite code has already been used.';
            }
            else
            {
                echo '<h1>Error</h1> The supplied invite code is invalid.';
            }
            return true;
        }
        // Note that we don't validate the password or username at all in this demo...
        $register_success = $controller->register($user, $pass, $user_java, $uuid_java, $uuid_bedrock, $email, $premium, $invite);
        if ($register_success)
        {
            $userinfo = $controller->getUserInfo($user);
            printf('<h1>Welcome, %s!</h1>Thanks for registering', htmlspecialchars($user));
            echo '<br />Password = ********';
            echo '<br />Fast Login = ' . $userinfo['premium'];
            echo '<br />Username(Java) = ' . $userinfo['user_java'];
            echo '<br />UUID(Java) = ' . $userinfo['uuid_java'];
            echo '<br />XUID(Bedrock) = ' . $userinfo['uuid_bedrock'];
            #            echo '<br /><a href="index.php">Back to form</a>';
            return true;
        }
        else
        {
            echo '<h1>Error</h1>Unfortunately, there was an error during the registration.';
        }
        return true;
    }
    return true;
}

function is_email_valid($email)
{
    return trim($email) === '' ? true // accept no email
     : filter_var($email, FILTER_VALIDATE_EMAIL);
}

?>

 </body>
</html>

