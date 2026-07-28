# Start a temporary PostgreSQL instance with a custom database and schema
run-db db_name="kubernix" sql_script="server/migrations/20260728_create_jobs_table.sql":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # 1. Create a truly temporary directory
    dir=$(mktemp -d)
    
    # 2. Ensure total cleanup on exit (even on errors)
    trap 'echo "Cleaning up $dir..."; rm -rf "$dir"' EXIT
    
    # 3. Copy the SQL script into the temp dir so it stays accessible
    cp "{{sql_script}}" "$dir/init.sql"
    
    echo "Initializing database in $dir..."
    nix-shell -p postgresql --run "
        set -x
        # Initialize cluster with postgres superuser
        initdb -D \"$dir/db\" -U postgres
       
        # Start server in the background using the temp dir for sockets
        postgres -D \"$dir/db\" -k \"$dir/db\" >/dev/null 2>&1 &
        PID=\$!
        
        # Wait for the socket file to become active
        echo \"Waiting for database to start...\"
        until [ -S \"$dir\"/db/.s.PGSQL.5432 ]; do sleep 0.1; done
        
        # Create the custom database and run the script
        echo \"Creating database: {{db_name}}\"
        createdb -h \"$dir/db\" -U postgres \"{{db_name}}\"
        
        echo \"Applying schema...\"
        psql -h \"$dir/db\" -U postgres -d \"{{db_name}}\" -f \"$dir/init.sql\"
        
        echo \"Database is ready! Connect using: just connect {{db_name}} \$(basename $dir)\"
        
        # Keep process alive until user presses Ctrl+C
        wait \"\$PID\"
    "

# Run an ephemeral, in-memory RustFS S3 mock server with custom credentials
s3-mock:
    #!/usr/bin/env sh
    export RUSTFS_ACCESS_KEY="my-dev-key"
    export RUSTFS_SECRET_KEY="my-dev-secret"
    mkdir -p /dev/shm/rustfs_data
    rustfs server --address :9000 /dev/shm/rustfs_data

server:
    export AWS_ACCESS_KEY_ID=my-dev-key
    export AWS_SECRET_ACCESS_KEY=my-dev-secret
    export AWS_ENDPOINT_URL="http://localhost:9000"
    export S3_BUCKET=kubernix
    cargo run -p kubernix-server
