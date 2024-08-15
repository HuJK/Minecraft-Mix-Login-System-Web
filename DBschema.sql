-- phpMyAdmin SQL Dump
-- version 5.0.4
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Generation Time: Aug 15, 2024 at 07:19 PM
-- Server version: 8.0.39-0ubuntu0.20.04.1
-- PHP Version: 7.4.3-4ubuntu2.23

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

--
-- Database: `mc_authdb`
--

-- --------------------------------------------------------

--
-- Table structure for table `authme`
--

CREATE TABLE `authme` (
  `id` int UNSIGNED NOT NULL,
  `username` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  `password` varchar(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `totp` varchar(32) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `ip` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `lastlogin` bigint DEFAULT NULL,
  `regdate` bigint NOT NULL DEFAULT '0',
  `regip` varchar(40) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `x` double NOT NULL DEFAULT '0',
  `y` double NOT NULL DEFAULT '0',
  `z` double NOT NULL DEFAULT '0',
  `world` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL DEFAULT 'world',
  `yaw` float DEFAULT NULL,
  `pitch` float DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `isLogged` smallint NOT NULL DEFAULT '0',
  `realname` varchar(255) NOT NULL,
  `hasSession` smallint NOT NULL DEFAULT '0',
  `invite` varchar(128) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- --------------------------------------------------------

--
-- Table structure for table `invite`
--

CREATE TABLE `invite` (
  `invite` varchar(128) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  `remain` int NOT NULL DEFAULT '1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- --------------------------------------------------------

--
-- Table structure for table `LinkedPlayers`
--

CREATE TABLE `LinkedPlayers` (
  `bedrockId` binary(16) NOT NULL,
  `javaUniqueId` binary(16) NOT NULL,
  `javaUsername` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- --------------------------------------------------------

--
-- Table structure for table `LinkedPlayersRequest`
--

CREATE TABLE `LinkedPlayersRequest` (
  `javaUsername` varchar(16) NOT NULL,
  `javaUniqueId` binary(16) NOT NULL,
  `linkCode` varchar(16) NOT NULL,
  `bedrockUsername` varchar(16) NOT NULL,
  `requestTime` bigint NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- --------------------------------------------------------

--
-- Table structure for table `premium`
--

CREATE TABLE `premium` (
  `UserID` int UNSIGNED NOT NULL,
  `UUID` char(36) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `Name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  `Premium` tinyint DEFAULT '1',
  `LastIp` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `LastLogin` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `Floodgate` int DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Triggers `premium`
--
DELIMITER $$
CREATE TRIGGER `update_authme_realname` AFTER UPDATE ON `premium` FOR EACH ROW BEGIN
    IF OLD.Name != NEW.Name THEN
        UPDATE authme
        SET authme.realname = NEW.Name
        WHERE authme.id = NEW.UserID;
    END IF;
END
$$
DELIMITER ;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `authme`
--
ALTER TABLE `authme`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `invite`
--
ALTER TABLE `invite`
  ADD PRIMARY KEY (`invite`);

--
-- Indexes for table `LinkedPlayers`
--
ALTER TABLE `LinkedPlayers`
  ADD PRIMARY KEY (`javaUniqueId`) USING BTREE,
  ADD UNIQUE KEY `bedrockId` (`bedrockId`) USING BTREE,
  ADD KEY `javaUsername` (`javaUsername`);

--
-- Indexes for table `LinkedPlayersRequest`
--
ALTER TABLE `LinkedPlayersRequest`
  ADD PRIMARY KEY (`javaUsername`),
  ADD KEY `requestTime` (`requestTime`);

--
-- Indexes for table `premium`
--
ALTER TABLE `premium`
  ADD PRIMARY KEY (`UserID`),
  ADD UNIQUE KEY `Name` (`Name`),
  ADD KEY `uuid_idx` (`UUID`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `authme`
--
ALTER TABLE `authme`
  MODIFY `id` int UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `premium`
--
ALTER TABLE `premium`
  MODIFY `UserID` int UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `LinkedPlayers`
--
ALTER TABLE `LinkedPlayers`
  ADD CONSTRAINT `LinkedPlayers_ibfk_1` FOREIGN KEY (`javaUsername`) REFERENCES `premium` (`Name`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;

