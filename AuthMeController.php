<?php
/*****************************************************************************
 * AuthMe website integration logic                                          *
 * ------------------------------------------------------------------------- *
 * Allows interaction with the AuthMe database (registration, password       *
 * verification). Don't forget to update the AUTHME_TABLE value and your     *
 * database credentials in getAuthmeMySqli().                                *
 *                                                                           *
 * Source: https://github.com/AuthMe/AuthMeReloaded/                         *
 *****************************************************************************/
require_once('variables.php');
abstract class AuthMeController
{
    const DB_URL = CONSTANTS::DB_URL;
    const DB_USER = CONSTANTS::DB_USER;
    const DB_PASS = CONSTANTS::DB_PASS;
    const DB_NAME = CONSTANTS::DB_NAME;
    const MC_SAVE_PATH = CONSTANTS::MC_SAVE_PATH;
    const MOJANG_API_USER = CONSTANTS::MOJANG_API_USER;
    const AUTHME_TABLE = CONSTANTS::AUTHME_TABLE;
    const FastLogin_TABLE = CONSTANTS::FastLogin_TABLE;
    const LinkedPlayer_TABLE = CONSTANTS::LinkedPlayer_TABLE;
    const AUTHME_INVITE_TABLE = CONSTANTS::AUTHME_INVITE_TABLE;
    /**
     * Entry point function to check supplied credentials against the AuthMe database.
     *
     * @param string $username the username
     * @param string $password the password
     * @return bool true iff the data is correct, false otherwise
     */
    function checkPassword($username, $password)
    {
        if (is_scalar($username) && is_scalar($password))
        {
            $hash = $this->getHashFromDatabase($username);
            if ($hash)
            {
                return $this->isValidPassword($password, $hash);
            }
        }
        return false;
    }
    function getOfflineUUID($username) {
        //extracted from the java code:
        //new GameProfile(UUID.nameUUIDFromBytes(("OfflinePlayer:" + name).getBytes(Charsets.UTF_8)), name));
        $data = hex2bin(md5("OfflinePlayer:" . $username));
        //set the version to 3 -> Name based md5 hash
        $data[6] = chr(ord($data[6]) & 0x0f | 0x30);
        //IETF variant
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        return bin2hex($data);
    }
    
    function removePrefix($prefix,$str){
        if (substr($str, 0, strlen($prefix)) == $prefix) {
            $str = substr($str, strlen($prefix));
        }
        return $str;
    }
    function safeRename($src_path, $dst_path){
        if (file_exists($src_path)){
            if (file_exists($dst_path)){
               if (!rename($dst_path, $dst_path . "_" . date("Ymd_His"))){
                    printf("Error: Failed to move %s to %s<br>", self::removePrefix(self::MC_SAVE_PATH . "/" ,$dst_path), self::removePrefix(self::MC_SAVE_PATH . "/",$dst_path . date("Ymd_His")));
                } else {
                    printf("Info: Move %s to %s succesfully<br>",self::removePrefix(self::MC_SAVE_PATH . "/",$dst_path), self::removePrefix(self::MC_SAVE_PATH . "/",$dst_path . date("Ymd_His")));
                } 
            }
            if (!rename($src_path, $dst_path)){
                printf("Error: Failed to move %s to %s<br>", self::removePrefix(self::MC_SAVE_PATH ."/",$src_path), self::removePrefix(self::MC_SAVE_PATH."/",$dst_path));
                return false;
            } else {
                printf("Info: Move %s to %s succesfully<br>",self::removePrefix(self::MC_SAVE_PATH."/",$src_path), self::removePrefix(self::MC_SAVE_PATH."/",$dst_path));
            }
            if (!copy($dst_path, $src_path)){
                printf("Error: Failed to copy %s to %s<br>", self::removePrefix(self::MC_SAVE_PATH ."/",$dst_path), self::removePrefix(self::MC_SAVE_PATH."/",$src_path));
            } else {
                printf("Info: Copy %s to %s succesfully<br>",self::removePrefix(self::MC_SAVE_PATH."/",$dst_path), self::removePrefix(self::MC_SAVE_PATH."/",$src_path));
                chmod($src_path,0664);
            }
        } else {
            printf("Info: %s Not found.<br>",$src_path);
        }
        return true;
    }
    function safeRenameUUID($formatstr,$src_uuid,$dst_uuid){
        $src_file = sprintf($formatstr, self::MC_SAVE_PATH, $src_uuid);
        $dst_file = sprintf($formatstr, self::MC_SAVE_PATH, $dst_uuid);
        return self::safeRename($src_file, $dst_file);
    }

    function getUuidWithDash($striped) {
        if($striped === null){
            return null;
        }
        //example: 069a79f4-44e9-4726-a5be-fca90e38aaf5
        $components = array(
            substr($striped, 0, 8),
            substr($striped, 8, 4),
            substr($striped, 12, 4),
            substr($striped, 16, 4),
            substr($striped, 20),
        );
        return implode('-', $components);
    }
    function getOnlineUUID($user_java){

        $mysqli = $this->getAuthmeMySqli();
        if ($mysqli !== null)
        {
            $stmt = $mysqli->prepare('SELECT Premium, UUID FROM ' . self::FastLogin_TABLE . ' WHERE Name = ?');
            $stmt->bind_param('s', $user_java);
            $stmt->execute();
            $stmt->bind_result($premium, $uuid_java);

            if ($stmt->fetch() !== false) {
                if ($uuid_java !== null){
                    return $uuid_java;
                }
            }
            $stmt->close();
        }

        $api_url = self::MOJANG_API_USER . $user_java;
        $response = file_get_contents($api_url);

        if ($response === false)
        {
            printf("Error: Unable to fetch data from the Mojang API %s.", $api_url);
            return null;
        }

        $data = json_decode($response, true);

        if (isset($data['id']))
        {
            return $data['id'];
        }
        else
        {
            printf("Error: User %s not in Mojang Server: %s.", $user_java, $api_url);
            return null;
        }
        return null;
    }
    function getUserInfo($username)
    {
        $mysqli = $this->getAuthmeMySqli();
        if ($mysqli !== null)
        {
            // Step 1: Get id and email from the AuthMe table
            $stmt = $mysqli->prepare('SELECT id, email, isLogged, lastlogin FROM ' . self::AUTHME_TABLE . ' WHERE username = ?');
            $stmt->bind_param('s', $username);
            $stmt->execute();
            $stmt->bind_result($id, $email, $isLogged, $last_login);
            $stmt_fetch_result = $stmt->fetch();
            if ($stmt_fetch_result === false)
            {
                printf('Error during AuthMe connection. Errno: %d, error: "%s"<br>', mysqli_connect_errno() , mysqli_connect_error());
                return null;
            }
            $stmt->close();

            // Step 2: Get Name and Premium from the FastLogin table using the fetched id
            $stmt_fastlogin = $mysqli->prepare('SELECT Name, Premium, UUID FROM ' . self::FastLogin_TABLE . ' WHERE UserID = ?');
            $stmt_fastlogin->bind_param('i', $id);
            $stmt_fastlogin->execute();
            $stmt_fastlogin->bind_result($name, $premium, $uuid_java);

            if (!($stmt_fastlogin->fetch()))
            {
                printf('Error during FastLogin connection. Errno: %d, error: "%s"<br>', mysqli_connect_errno() , mysqli_connect_error());
                return null;
            }
            $stmt_fastlogin->close();

            // Step 3: Get the existing bedrock link by UUID
            $stmt_bedrocklink = $mysqli->prepare('SELECT HEX(bedrockId) FROM ' . self::LinkedPlayer_TABLE . ' WHERE javaUniqueId = UNHEX(?)');
            $stmt_bedrocklink->bind_param('s', $uuid_java);
            $stmt_bedrocklink->execute();
            $stmt_bedrocklink->bind_result($uuid_bedrock);

            if (!($stmt_bedrocklink->fetch()))
            {
                $uuid_bedrock = null;
            } else {
                $uuid_bedrock = ltrim($uuid_bedrock, '0');
                $uuid_bedrock = str_pad($uuid_bedrock, 16, "0", STR_PAD_LEFT);
                $uuid_bedrock = strtolower($uuid_bedrock);
            }
            $stmt_bedrocklink->close();

            // retuen the result
            $result = ['isLogged' => $isLogged, 'email' => $email, 'user_java' => $name, 'uuid_java' => $uuid_java, 'uuid_bedrock' => $uuid_bedrock, 'last_login' => $last_login, 'premium' => $premium === 1 ? "1" : "0", ];
            return $result;
        }

        return null; // Return null if the connection to the database could not be established
        
    }
    /**
     * Returns whether the user exists in the database or not.
     *
     * @param string $username the username to check
     * @return bool true if the user exists; false otherwise
     */
    function isUserRegistered($username,$user_java)
    {
        $mysqli = $this->getAuthmeMySqli();
        if ($mysqli !== null)
        {
            $stmt = $mysqli->prepare('SELECT 1 FROM ' . self::AUTHME_TABLE . ' WHERE username = ? OR realname = ?');
            $stmt->bind_param('ss', $username, $user_java);
            $stmt->execute();
            return $stmt->fetch();
        }

        // Defensive default to true; we actually don't know
        return true;
    }

    function useInviteCode($invite)
    {
        $mysqli = $this->getAuthmeMySqli();
        $remain = 0;
        if ($mysqli !== null)
        {
            $stmt = $mysqli->prepare('SELECT remain FROM ' . self::AUTHME_INVITE_TABLE . ' WHERE invite = ?');
            $stmt->bind_param('s', $invite);
            $stmt->execute();
            $stmt->bind_result($remain);
            if ($stmt->fetch() == false)
            {
                return "Invalid";
            }
            if ($remain === 0)
            {
                return "Already used";
            }
            if ($remain > 0)
            {
                $mysqli = $this->getAuthmeMySqli();
                $stmt = $mysqli->prepare('UPDATE ' . self::AUTHME_INVITE_TABLE . ' SET remain = remain -1 WHERE invite = ?');
                $stmt->bind_param('s', $invite);
                $stmt->execute();
            }
            return "OK";
        }

        // Defensive default to false; we actually don't know
        return "DB error";
    }

    /**
     * Registers a player with the given username.
     *
     * @param string $username the username to register
     * @param string $password the password to associate to the user
     * @param string $email the email (may be empty)
     * @return bool whether or not the registration was successful
     */
    function register($username, $password, $user_java, $uuid_java, $uuid_bedrock, $email, $premium, $invite)
    {
        $email = $email ? $email : 'your@email.com';
        $mysqli = $this->getAuthmeMySqli();
        if ($mysqli !== null) {
            if ( $premium === "1") {
                $uuid_java_from_api=self::getOnlineUUID($user_java);
                if ($uuid_java_from_api===null){
                    return false;
                }
                else if ($uuid_java_from_api !== $uuid_java)
                    {
                        printf("Error: User provided UUID: %s does not match the response Mojang API: %s .",$uuid_java,$uuid_java_from_api);
                        return false;
                    } 
            } else {
                $uuid_java=null;
            }

            $hash = $this->hash($password);
            $stmt = $mysqli->prepare('INSERT INTO ' . self::AUTHME_TABLE . ' (username, realname, password, email, regip, invite) ' . 'VALUES (?       , ?       , ?       , ?    , ?    , ?)');
            $user_ip = $_SERVER['REMOTE_ADDR'];
            if (!empty($_SERVER["HTTP_CF_CONNECTING_IP"])) {
                $user_ip = $_SERVER["HTTP_CF_CONNECTING_IP"];
            }
            $stmt->bind_param('ssssss', $username, $user_java, $hash, $email, $user_ip, $invite);
            $stmt_result = $stmt->execute();
            if ($stmt_result === false) {
                printf('Error during AuthMe connection. Errno: %d, error: "%s"', mysqli_connect_errno($mysqli) , mysqli_connect_error($mysqli));
                return $stmt_result;
            }

            $stmt_insert_id = mysqli_insert_id($mysqli);

            if ($stmt_insert_id === 0) {
                printf('Error: mysqli_insert_id($mysqli) === 0');
                return false;
            }

            $stmt_fastlogin = $mysqli->prepare('INSERT INTO ' . self::FastLogin_TABLE . ' (UserID, UUID, Name, Premium) ' . 'VALUES (?     , ?   , ?   , ? )');
            $stmt_fastlogin ->bind_param('ssss', $stmt_insert_id, $uuid_java, $user_java, $premium);
            $stmt_fastlogin_result = $stmt_fastlogin->execute();
            if ($stmt_fastlogin_result === false) {
                printf('Error during Fastlogin connection. Errno: %d, error: "%s"', mysqli_connect_errno($mysqli) , mysqli_connect_error($mysqli));
                return $stmt_fastligin_result;
            }

/*            if ($uuid_bedrock !== null){
                $uuid_bedrock = str_pad($uuid_bedrock, 32, "0", STR_PAD_LEFT);
                $uuid_java = str_pad($uuid_java, 32, "0", STR_PAD_LEFT);
                $stmt_link = $mysqli->prepare('INSERT INTO ' . self::LinkedPlayer_TABLE . ' (bedrockId, javaUniqueId, javaUsername) VALUES (UNHEX(?), UNHEX(?), ?)');
                $stmt_link ->bind_param('sss', $uuid_bedrock, $uuid_java, $user_java);
                $stmt_link_result = $stmt_link->execute();
                if ($stmt_link_result === false) {
                    printf('Error during LinkedPlayer connection. Errno: %d, error: "%s"', mysqli_connect_errno($mysqli) , mysqli_connect_error($mysqli));
                    return $stmt_link_result;
                }
            }*/
            return true;
        }
        return false;
    }

    /**
     * Changes password for player.
     *
     * @param string $username the username
     * @param string $password the password
     * @return bool true whether or not password change was successful
     */
    function changePassword($username, $password)
    {
        $mysqli = $this->getAuthmeMySqli();
        if ($mysqli !== null)
        {
            $hash = $this->hash($password);
            $stmt = $mysqli->prepare('UPDATE ' . self::AUTHME_TABLE . ' SET password=? ' . 'WHERE username=?');
            $stmt->bind_param('ss', $hash, $username);
            return $stmt->execute();
        }
        return false;
    }

    function changeEmail($username, $email)
    {
        $mysqli = $this->getAuthmeMySqli();
        if ($mysqli !== null)
        {
            $stmt = $mysqli->prepare('UPDATE ' . self::AUTHME_TABLE . ' SET email=? WHERE username=?');
            $stmt->bind_param('ss', $email, $username);
            return $stmt->execute();
        }
        return false;
    }
    function changePremium($username, $premium)
    {
        $mysqli = $this->getAuthmeMySqli();
        if ($mysqli !== null)
        {
            $userinfo = $this->getUserInfo($username);
            if ($userinfo === null){
                echo 'Error: Failed to get userinfo<br>';
                return null;
            }
            if ($userinfo["isLogged"]===1){
                echo 'Error: Player is online. Please exit the game before update.<br>';
                return null;
            }
            if ($userinfo["premium"] == $premium){
                // Do nothing
                return true;
            }
            $src_uuid="";
            $dst_uuid="";
            $offlineUUID = self::getOfflineUUID($userinfo["user_java"]);
            // $uuid_java can't be change as long as it has been set.
            $onlineUUID = $userinfo["uuid_java"];
            if ($onlineUUID === null){
                $onlineUUID = self::getOnlineUUID($userinfo["user_java"]);
            }
            $offlineUUID_dash = self::getUuidWithDash($offlineUUID);
            $onlineUUID_dash = self::getUuidWithDash($onlineUUID);
            if ($userinfo["premium"] === "0" && $premium === "1"){
                // If user changes from offline to online
                if ($onlineUUID !== null){
                    // From offline to online
                    $src_uuid = $offlineUUID_dash;
                    $dst_uuid = $onlineUUID_dash;
                }
                else {
                    printf("Failed to get online UUID, user %s does not exist on Mojang Server", $username);
                    return null;
                }
    
            } else if ($userinfo["premium"] === "1" && $premium === "0"){
                // From online to offline
                if ($onlineUUID !== null){
                    $src_uuid = $onlineUUID_dash;
                    $dst_uuid = $offlineUUID_dash;
                }
                else {
                    //Failed to get online UUID, ignores
                }
                // clear bedrock link
                if ($userinfo["uuid_bedrock"] !== null){
                    print("Going to clear<br>");
                    $uuid_java = $userinfo["uuid_java"];
                    $stmt_link = $mysqli->prepare('DELETE FROM ' . self::LinkedPlayer_TABLE . ' WHERE javaUniqueId = UNHEX(?)');
                    $stmt_link->bind_param('s', $uuid_java);
                    $stmt_link_result = $stmt_link->execute();
                    printf('DELETE FROM ' . self::LinkedPlayer_TABLE . ' WHERE javaUniqueId = UNHEX(%s)<br>',$uuid_java);
                    if ($stmt_link_result === false) {
                        printf('Error during LinkedPlayer deletion. Errno: %d, error: "%s"', $stmt_delete->errno, $stmt_delete->error);
                    }
                }
            } else {
                print_r($userinfo);
                printf("Error: Unknown state: oldstate: %s, newstate: %s",$userinfo["premium"],$premium);
            }
    
            if ($onlineUUID !== null){
                $src_file_playerdata = sprintf("%s/world/playerdata/%s.dat", self::MC_SAVE_PATH, $src_uuid);
                $dst_file_playerdata = sprintf("%s/world/playerdata/%s.dat", self::MC_SAVE_PATH, $dst_uuid);
                $src_file_slimefun = sprintf("%s/data-storage/Slimefun/Players/%s.yml", self::MC_SAVE_PATH, $src_uuid);
                $dst_file_slimefun = sprintf("%s/data-storage/Slimefun/Players/%s.yml", self::MC_SAVE_PATH, $dst_uuid);

                self::safeRenameUUID("%s/world/playerdata/%s.dat",$src_uuid, $dst_uuid);
                //self::safeRenameUUID("%s/world/playerdata/%s.dat_old",$src_uuid, $dst_uuid);
                self::safeRenameUUID("%s/data-storage/Slimefun/Players/%s.yml",$src_uuid, $dst_uuid);
                self::safeRenameUUID("%s/data-storage/Slimefun/waypoints/%s.yml",$src_uuid, $dst_uuid);
            }
    
            $stmt = $mysqli->prepare('SELECT id, email FROM ' . self::AUTHME_TABLE . ' WHERE username = ?');
            $stmt->bind_param('s', $username);
            $stmt->execute();
            $stmt->bind_result($id, $email);
            $stmt_fetch_result = $stmt->fetch();
            if ($stmt_fetch_result === false)
            {
                printf('Error during AuthMe connection. Errno: %d, error: "%s"', mysqli_connect_errno() , mysqli_connect_error());
                return null;
            }
            $stmt->close();
            $premium = ($premium === "1" ? 1 : 0);
            if($premium===1){
                $stmt = $mysqli->prepare('UPDATE ' . self::AUTHME_TABLE . ' SET lastlogin = null WHERE username = ?');
                $stmt->bind_param('s', $username);
                $stmt->execute();
                $stmt->close();
            }
            if ($userinfo["uuid_java"] === null){
                $stmt_fastlogin = $mysqli->prepare('UPDATE ' . self::FastLogin_TABLE . ' SET Premium=?, UUID=? WHERE UserID=?');
                $stmt_fastlogin->bind_param('ssi', $premium,$onlineUUID, $id);
            } else {
                $stmt_fastlogin = $mysqli->prepare('UPDATE ' . self::FastLogin_TABLE . ' SET Premium=? WHERE UserID=?');
                $stmt_fastlogin->bind_param('si', $premium, $id);
            }
            return $stmt_fastlogin->execute();
        }
        return true;
    }

    function changeBedrockXUID($username, $uuid_bedrock)
    {
        $mysqli = $this->getAuthmeMySqli();
        if ($mysqli !== null)
        {
            $userinfo = $this->getUserInfo($username);
            if ($userinfo === null){
                echo 'Error: Failed to get userinfo<br>';
                return null;
            }
            if ($userinfo["isLogged"]===1){
                echo 'Error: Player is online. Please exit the game before update.<br>';
                return null;
            }
            if ($uuid_bedrock !== null){
                if ($userinfo["premium"] === "0"){
                    echo 'Error: Only Mojang account can link to bedrock client.<br>';
                    return null;
                }
                if ($userinfo["uuid_java"] === null){
                    echo 'Error: You have to login at least once at game with Mojang Account before link to the bedrock client.<br>';
                    return null;
                }
                if ($userinfo["last_login"] === null){
                    echo 'Error: You have to login at least once at game with Mojang Account to verify the UUID(Java) is valid before link to the bedrock client.<br>';
                    return null;
                }
            }

            $uuid_java = str_pad($userinfo["uuid_java"], 32, "0", STR_PAD_LEFT);

            if ($userinfo["uuid_bedrock"] == $uuid_bedrock){
                // Do nothing
                return true;
            }
            if ($uuid_bedrock === null){
                $stmt_link = $mysqli->prepare('DELETE FROM ' . self::LinkedPlayer_TABLE . ' WHERE javaUniqueId = UNHEX(?)');
                $stmt_link->bind_param('s', $uuid_java);
                $stmt_link_result = $stmt_link->execute();
                if ($stmt_link_result === false) {
                    printf('Error during LinkedPlayer deletion. Errno: %d, error: "%s"', $stmt_delete->errno, $stmt_delete->error);
                    return $stmt_delete_result;
                }
            } else {
                // Prepare the SQL statement with ON DUPLICATE KEY UPDATE
                $uuid_bedrock = str_pad($uuid_bedrock, 32, "0", STR_PAD_LEFT);


                $stmt_check = $mysqli->prepare('SELECT HEX(javaUniqueId), javaUsername FROM ' . self::LinkedPlayer_TABLE . ' WHERE bedrockId = UNHEX(?)');
                $stmt_check->bind_param('s', $uuid_bedrock);
                $stmt_check->execute();
                $stmt_check->store_result();

                if ($stmt_check->num_rows > 0) {
                    $stmt_check->bind_result($existing_uuid_java, $existing_java_username);
                    $stmt_check->fetch();

                    // If the existing javaUniqueId doesn't match the current one, return an error
                    if ($existing_uuid_java !== $uuid_java) {
                        printf('Error: XUID(Bedrock): %s has been linked to UUID(Java): %s with Username %s', str_pad(ltrim($uuid_bedrock, '0'),16,"0", STR_PAD_LEFT), $existing_uuid_java, $existing_java_username);
                        return false;
                    }
                }

                $stmt_link = $mysqli->prepare('
                    INSERT INTO ' . self::LinkedPlayer_TABLE . ' (bedrockId, javaUniqueId, javaUsername)
                    VALUES (UNHEX(?), UNHEX(?), ?)
                    ON DUPLICATE KEY UPDATE
                    bedrockId = UNHEX(?)');
                
                // Bind parameters: three inputs for insert and two for the update
                $stmt_link->bind_param('ssss', $uuid_bedrock, $uuid_java, $userinfo["user_java"], $uuid_bedrock);
                
                $stmt_link_result = $stmt_link->execute();
                
                if ($stmt_link_result === false) {
                    printf('Error during LinkedPlayer connection. Errno: %d, error: "%s"', $stmt_link->errno, $stmt_link->error);
                    return $stmt_link_result;
                }
            }
        }
        return true;
    }

    function changeUserJava($username, $user_java)
    {
        if (strlen($user_java) === 0)
        {
            printf('Error: $user_java can\'t be empty.');
            return false;
        }
        $mysqli = $this->getAuthmeMySqli();
        if ($mysqli !== null)
        {
            $stmt = $mysqli->prepare('SELECT id, email FROM ' . self::AUTHME_TABLE . ' WHERE username = ?');
            $stmt->bind_param('s', $username);
            $stmt->execute();
            $stmt->bind_result($id, $email);
            $stmt_fetch_result = $stmt->fetch();
            if ($stmt_fetch_result === false)
            {
                printf('Error during AuthMe connection. Errno: %d, error: "%s"', mysqli_connect_errno() , mysqli_connect_error());
                return false;
            }
            $stmt->close();

            $stmt_fastlogin = $mysqli->prepare('UPDATE ' . self::FastLogin_TABLE . ' SET Name=? WHERE UserID=?');
            $stmt_fastlogin->bind_param('ss', $user_java, $id);
            return $stmt_fastlogin->execute();
        }
        return true;
    }

    /**
     * Hashes the given password.
     *
     * @param $password string the clear-text password to hash
     * @return string the resulting hash
     */
    protected abstract function hash($password);

    /**
     * Checks whether the given password matches the hash.
     *
     * @param $password string the clear-text password
     * @param $hash string the password hash
     * @return boolean true if the password matches, false otherwise
     */
    protected abstract function isValidPassword($password, $hash);

    /**
     * Returns a connection to the database.
     *
     * @return mysqli|null the mysqli object or null upon error
     */
    private function getAuthmeMySqli()
    {
        // CHANGE YOUR DATABASE DETAILS HERE BELOW: host, user, password, database name
        $mysqli = new mysqli(self::DB_URL, self::DB_USER, self::DB_PASS, self::DB_NAME);
        if (mysqli_connect_error())
        {
            printf('Could not connect to AuthMe database. Errno: %d, error: "%s"', mysqli_connect_errno() , mysqli_connect_error());
            return null;
        }
        return $mysqli;
    }

    /**
     * Retrieves the hash associated with the given user from the database.
     *
     * @param string $username the username whose hash should be retrieved
     * @return string|null the hash, or null if unavailable (e.g. username doesn't exist)
     */
    private function getHashFromDatabase($username)
    {
        $mysqli = $this->getAuthmeMySqli();
        if ($mysqli !== null)
        {
            $stmt = $mysqli->prepare('SELECT password FROM ' . self::AUTHME_TABLE . ' WHERE username = ?');
            $stmt->bind_param('s', $username);
            $stmt->execute();
            $stmt->bind_result($password);
            if ($stmt->fetch())
            {
                return $password;
            }
        }
        return null;
    }

}


