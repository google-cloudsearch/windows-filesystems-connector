# Google Cloud Search Windows File Systems Connector

The Google Cloud Search Windows File Systems Connector enables indexing Microsoft Windows File
Systems including SMB, DFS, and Windows File Share, with support for ACLs and instant change
detection. This connector implements the graph traversal strategy provided by the
[Content Connector SDK](https://developers.google.com/cloud-search/docs/guides/content-connector).

Before running the Windows File Systems Connector, you must map the principals used in
Windows ACLs to identities in the Google Cloud Identity service. See the
[configuration documentation](https://developers.google.com/cloud-search/docs/guides/filesystem-connector#configure-datasource-access)
for more information about setting up an identity source.


## Build instructions

1. Build the connector

   a. Clone the connector repository from GitHub:
      ```
      git clone https://github.com/google-cloudsearch/windows-filesystems-connector.git
      cd windows-filesystems-connector
      ```

   b. Checkout the desired version of the connector and build the ZIP file:
      ```
      git checkout tags/v1-0.0.5
      mvn package
      ```
      (To skip the tests when building the connector, use `mvn package -DskipTests`)


2. Install the connector

   The `mvn package` command creates a ZIP file containing the
   connector and its dependencies with a name like
   `google-cloudsearch-windows-filesystems-connector-v1-0.0.5.zip`.

   a. Copy this ZIP file to the location where you want to install the connector.

   b. Unzip the connector ZIP file. A directory with a name like
      `google-cloudsearch-windows-filesystems-connector-v1-0.0.5` will be created.

   c. Change into this directory. You should see the connector jar file,
      `google-cloudsearch-windows-filesystems-connector-v1-0.0.5.jar`, as well as a `lib`
      directory containing the connector's dependencies.


3. Configure the connector

   a. Create a file containing the connector configuration parameters. Refer to the
   [configuration documentation](https://developers.google.com/cloud-search/docs/guides/filesystem-connector#specify-configuration)
   for specifics and for parameter details.


4. Run the connector

   The connector should be run from the unzipped installation directory, **not** the source
   code's `target` directory.

   ```
   java \
      -jar google-cloudsearch-windows-filesystems-connector-v1-0.0.5.jar \
      -Dconfig=my.config
   ```

   Where `my.config` is the configuration file containing the parameters for the
   connector execution.

   **Note:** If the configuration file is not specified, a default file name of
   `connector-config.properties` will be assumed.


For further information on configuration and deployment of this connector, see
[Deploy the Microsoft Windows File Systems Connector](https://developers.google.com/cloud-search/docs/guides/filesystem-connector).
