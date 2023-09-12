# Contributing to the Project
Everyone is encouraged to participate in the SPDX Software Bill of Materials (SBOM) Generator project. Anyone can influence the project by simply being involved in the discussions about new features, the roadmap, architecture, and even problems they are facing.

Community meetings are held every Wednesday, 9:30am-10:30am Pacific (12:30pm-1:30pm EDT, 5:30pm-6:30pm UTC), online. Join the meeting [here](https://meet.jit.si/SBOM-tools)

Meeting minutes are recorded [here](https://hackmd.io/EQ0DwvvgRnOl2uzPiTYQcw).

This is the process we suggest for contributions. This process is designed to reduce the burden on project reviews, impact on other contributors, and to keep the amount of rework from the contributor to a minimum.

SPDX-License-Identifier: CC-BY-4.0 

Each new ***documentation related file*** must conatin this SPDX short-form identifier as mentioned above. For details, see [License Information](license-information) section of this document.

1. [Create a Fork of spdx-sbom-generator](https://github.com/opensbom-generator/spdx-sbom-generator) to your personal GitHub account by clicking the fork button on the top right corner of the spdx-sbom-genrator project repo page in GitHub.
2. Clone the forked repo to your local machine. For details, see [Creating a Fork](https://gist.github.com/Chaser324/ce0505fbed06b947d962#creating-a-fork).
3. On your development computer, navigate to the ***spdx-sbom-generator*** folder that was created when you cloned the project.

4. Rename the default remote pointing to the upstream repository from origin to upstream:
    ```
    git remote rename origin upstream
    ```
    Ensure that you let Git know about the fork you just created, naming it origin:

    ```
    git remote add origin https://github.com/<your github id>/spdx-sbom-generator
    ```
    and verify the remote repos:

    ```
    git remote -v
    ```
    The output should look similar to:
    
```
    origin   https://github.com/<your github id>/spdx-sbom-generator (fetch)
    origin   https://github.com/<your github id>/spdx-sbom-generator (push)
    upstream https://github.com/opensbom-generator/spdx-sbom-generator (fetch)
    upstream https://github.com/opensbom-generator/spdx-sbom-generator (push)
```
5. create a branch (off of main) for your work. If you’re addressing an issue, we suggest you to include the issue type as the branch name, for example:
    ```
    git checkout main
    git checkout -b fix_typo
    ```
4. Make changes to the project.
5. When things look good, start the pull request process by adding your changed files:

    ```
    git add [file(s) that changed, add -p if you want to be more specific]
    ```
    You can see files that are not yet staged using:

    ```
    git status
    ```
6. Commit your changes to your local repo:

 ```
 git commit -s
 ```
 The ```-s``` option automatically adds your ```Signed-off-by:``` to your commit message. Your commit will be rejected without this line.
    
 Adding ```Sign-off-by``` while commiting changes indicates your agreement with the [Developer Certificate of Origin (DCO)](https://developercertificate.org/), a copy of which is included below.

7. Push your topic branch with your changes to your forked personal GitHub account:
    ```
    git push origin <branch name>
    ```
7. In your web browser, go to your forked repo and click on the ```Compare & pull request``` button for the branch you just worked on that you want to open a pull request with.
8. Review the pull request changes, and verify that you are opening a pull request for the appropriate branch. The title and message from your commit message should appear as well.
9. Click on the submit button and your pull request is sent and awaits review. Email will be sent as review comments are made, or you can check on your pull request at https://github.com/opensbom-generator/spdx-sbom-generator/pulls.

## License information

1. Each new **code realted file** should include a [SPDX short-form identifier](https://spdx.org/ids) at the top, indicating the project license for code, which is ***Apache-2.0***. This should look like the following:

```code
// SPDX-License-Identifier: Apache-2.0
```

2. Each new **documentation related file** should include a [SPDX short-form identifier](https://spdx.org/ids) at the top (as included in this doc), indicating the project license for documentation, which is ***CC-BY-4.0***. This should look like the following:

```text
SPDX-License-Identifier: CC-BY-4.0
```

## Developer Certificate of Origin \(DCO\)

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA, 94129

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```
