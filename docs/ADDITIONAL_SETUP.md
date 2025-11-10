# Additional Setup

This guide covers some optional configuration steps to get the best experience from Open OSCAR Server.

- [Configure User Directory Keywords](#configure-user-directory-keywords)
- [Import AIM Smiley Packs](#import-aim-smiley-packs)

## Configure User Directory Keywords

AIM users can make themselves searchable by interest in the user directory by configuring up to 5 interest keywords.

Two types of keywords are supported: categorized keywords, which belong to a specific category (e.g., Books, Music), and
top-level keywords, which appear at the top of the menu and are not associated with any category.

Open OSCAR Server does not come with any keywords installed out of the box. The following steps explain how to add
keywords and keyword categories via the management API.

1. **Add Categories**

   ###### Windows PowerShell

   ```powershell
   Invoke-WebRequest -Uri "http://localhost:8080/directory/category" `
    -Method POST `
    -ContentType "application/json" `
    -Body '{"name": "Programming Languages"}'

   Invoke-WebRequest -Uri "http://localhost:8080/directory/category" `
    -Method POST `
    -ContentType "application/json" `
    -Body '{"name": "Books"}'

   Invoke-WebRequest -Uri "http://localhost:8080/directory/category" `
    -Method POST `
    -ContentType "application/json" `
    -Body '{"name": "Music"}'
   ```

   ###### macOS / Linux / FreeBSD

    ```shell
    curl -d'{"name": "Programming Languages"}' http://localhost:8080/directory/category
    curl -d'{"name": "Books"}' http://localhost:8080/directory/category
    curl -d'{"name": "Music"}' http://localhost:8080/directory/category
    ```

2. **List Categories**

   Retrieve a list of all keyword categories created in the previous step.

   ###### Windows PowerShell

   ```powershell
   Invoke-WebRequest -Uri "http://localhost:8080/directory/category" -Method GET
   ```

   ###### macOS / Linux / FreeBSD

    ```shell
    curl http://localhost:8080/directory/category
    ```

   This output shows the categories and their corresponding IDs, which you will use to assign keywords in the next step.

    ```json
    [
      {
        "id": 2,
        "name": "Books"
      },
      {
        "id": 3,
        "name": "Music"
      },
      {
        "id": 1,
        "name": "Programming Languages"
      }
    ]
    ```

3. **Add Keywords**

   The first 3 requests set up keywords for books, music, and programming languages categories using the category IDs
   from the previous step. This last request adds a single top-level keyword with no category ID.

   ###### Windows PowerShell

   ```powershell
   Invoke-WebRequest -Uri "http://localhost:8080/directory/keyword" `
      -Method POST `
      -ContentType "application/json" `
      -Body '{"category_id": 2, "name": "The Dictionary"}'

   Invoke-WebRequest -Uri "http://localhost:8080/directory/keyword" `
      -Method POST `
      -ContentType "application/json" `
      -Body '{"category_id": 3, "name": "Rock"}'

   Invoke-WebRequest -Uri "http://localhost:8080/directory/keyword" `
      -Method POST `
      -ContentType "application/json" `
      -Body '{"category_id": 1, "name": "golang"}'

   Invoke-WebRequest -Uri "http://localhost:8080/directory/keyword" `
      -Method POST `
      -ContentType "application/json" `
      -Body '{"name": "Live, laugh, love!"}'
   ```

   ###### macOS / Linux / FreeBSD

    ```shell
    curl -d'{"category_id": 2, "name": "The Dictionary"}' http://localhost:8080/directory/keyword
    curl -d'{"category_id": 3, "name": "Rock"}' http://localhost:8080/directory/keyword
    curl -d'{"category_id": 1, "name": "golang"}' http://localhost:8080/directory/keyword
    curl -d'{"name": "Live, laugh, love!"}' http://localhost:8080/directory/keyword
    ```

   Fully rendered, the keyword list looks like this in the AIM client:

    <p align="center">
        <img width="500" alt="screenshot of AIM interests keywords menu" src="https://github.com/user-attachments/assets/f5295867-b74e-4566-879f-dfd81b2aab08">
    </p>

   Check out the [API Spec](../api.yml) for more details on directory API endpoints.

4. **Restart**

   After creating or modifying keyword categories and keywords, users currently connected to the server must sign out
   and back in again in order to see the updated keyword list.

## Import AIM Smiley Packs

AIM emoticons (also called smileys) are the graphics that appear when users send messages with specific codes like `:)`
or `:D`. Open OSCAR Server includes a BART import utility that allows you to import smiley pack collections.

This guide shows you how to install a smiley pack available
from [The Internet Archive](https://archive.org/details/aol_instant_messenger_smiley_packs).

1. **Download Smiley Pack**

   First download the smiley pack archive.

   ```bash
   curl -L -o aim_bart_emoticons.zip "https://archive.org/download/aol_instant_messenger_smiley_packs/aim_bart_emoticons.zip"
   ```

   Then extract the archive:

   ```bash
   unzip aim_bart_emoticons.zip
   ```

   This creates an `aim_bart_emoticons/` directory containing 86 files (1 per pack) with hash names like `0201D213A4`,
   `0201D205C8`, etc.

2. **Import Emoticons**

   From the root of the Open OSCAR Server repository, run the BART import script to upload the smiley pack:

    ```bash
    ./scripts/import_bart.sh -t emoticon_set -u http://localhost:8080 /path/to/aim_bart_emoticons/*
    ```

   Replace `/path/to/aim_bart_emoticons/*` with the actual path to your extracted directory.

3. **Verify Import Success**

   Check that all emoticons were imported successfully:

   ```bash
   curl "http://localhost:8080/bart?type=1024"
   ```

4. **Send an Emoticon**

   After importing, you can test the emoticons in AIM clients by sending messages with emoticon codes. For example, the
   classic smiley emoticon can be tested with:

   ```
   <font sml="KwAAAeQ=">:)</font>
   ```

   This code references the smiley pack with hash `2B000001E4` that should now be available in your server.