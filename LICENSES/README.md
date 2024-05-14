# Licenses in Spyderisk Adaptor and how to apply them

This is both a policy document and a practical how-to. The technical details of
licensing can be complicated, but Spyderisk licensing is easy if you follow
these basic rules. If you have any questions do please ask
[team@spyderisk.org](mailto://team@spyderisk.org).

Licenses apply to all intellectual property in the Spyderisk Open project.
Within individual source files, we specify licensing according to the 
[SPDX software component Bill of Materials](https://spdx.dev/) specification. For code
that we create, we choose the license. For third-party code, we use whatever license 
was chosen for that code (assuming it is compatible with Spyderisk at all - otherwise
we couldn't use that third-party code!)

We currently use these licenses in Spyderisk Deployment:

* *[Apache 2](./APACHE-2.0.txt)* for nearly all code, including all code created specifically for Spyderisk
* *[Creative Commons By-SA 4.0](./CREATIVE-COMMONS-BY-SA-4.0.txt)* for all new documentation, and eventually all documentation will be copyright CC By SA unless it was created by someone 

Spyderisk is happy to consider any useful third-party code or
documentation for inclusion in Spyderisk provided it is under a compatible
license. There is occasionally some nuance to what "compatible license" means,
as described below, but this is our general intention.

# Apache 2.0 license - default for source code

In some cases other licenses may be used if the code originated from a third party.
So long as the third party code has a license compatible with the
[Open Source Definition](https://opensource.org/osd/) then it will not conflict with
the Apache 2.0 license and we can freely use it.

In order to apply the Apache license to a source code file in the Spyderisk
project, insert the following comment block at the top, replacing the text in
[square brackets] with the correct values.

```
Copyright [YEAR] The Spyderisk Licensors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

<!-- SPDX-License-Identifier: Apache 2.0 -->
<!-- SPDX-FileCopyrightText: [YEAR] The Spyderisk Licensors -->
<!-- SPDX-ArtifactOfProjectName: Spyderisk -->
<!-- SPDX-FileType: Source code -->
<!-- SPDX-FileComment: Original by [NAME OF CONTRIBUTOR], [MONTH] [YEAR] -->
```

# Creative Commons BY-SA - documentation and config files

We have decided not to apply copyright headers to README files such as the one you are reading, because
the REUSE standard already brands every file, and it would just be messy and distracting.
Similarly we do not add copyright headers to images, we just make a statement in a file 
covering all the images. However most non-Markdown forms of documentation do have explicit CC BY-SA
license at the top.

```
Copyright 2023 The Spyderisk Authors

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2023 The Spyderisk Authors -->
<!-- SPDX-ArtifactOfProjectName: Spyderisk -->
<!-- SPDX-FileType: Documentation -->
<!-- SPDX-FileComment: Original by Dan Shearer, October 2023 -->
```

# What about third-party GPL code?

No, because:

* GPLv2 isn't compatible with Apache 2, and
* other GPL licenses are compatible but for this deployment project its likely more hassle than its work.

This is more relevant to the GPL section in the [Spyderisk source licensing discussion](https://github.com/Spyderisk/system-modeller/blob/dev/LICENSES/README.md), so you can read detailed commentary there.
