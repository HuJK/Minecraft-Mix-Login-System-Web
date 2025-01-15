#!/bin/bash

# Define the path to your PHP file
php_file="variables.php"

# Extract the MC_SAVE_PATH value using grep, tr, and sed
MC_SAVE_PATH=$(grep -Pzo "(?s)public\s+const\s+MC_SAVE_PATH\s*=\s*'([^']+)';" "$php_file" | tr -d '\0' | sed -E "s/.*'([^']+)'.*/\1/")

# Print the result
echo "MC_SAVE_PATH: $MC_SAVE_PATH"
chmod 660 "$MC_SAVE_PATH/world/playerdata/"*
chmod 660 "$MC_SAVE_PATH/data-storage/Slimefun/Players/"*
chmod 660 "$MC_SAVE_PATH/data-storage/Slimefun/waypoints/"*
