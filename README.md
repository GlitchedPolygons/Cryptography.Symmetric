[![AppVeyor](https://ci.appveyor.com/api/projects/status/tkf68xbsdoa1ttfq/branch/master?svg=true)](https://ci.appveyor.com/project/GlitchedPolygons/netstandard2-0-class-lib/branch/master) [![Travis](https://travis-ci.org/GlitchedPolygons/netstandard2.0-class-lib.svg?branch=master)](https://travis-ci.org/GlitchedPolygons/netstandard2.0-class-lib) [![CircleCI](https://circleci.com/gh/GlitchedPolygons/netstandard2.0-class-lib.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/netstandard2.0-class-lib) 

# TO DO

## Describe the netstandard2.0 class library here.

Explain how to install it, what dependencies it has, how to quickly get started (maybe link to some more detailed _Getting Started_ guide somewhere else), where to find extensive API docs, how to build from source, stuff like that, etc...

Remember to rename the project and its namespace. Then customize the .csproj file to match your choices (root namespace and assembly name fields). 

Finally, consider making your library open source by adding a permissive license such as the [MIT](https://en.wikipedia.org/wiki/MIT_License) or the [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) license to your repo root and replacing the placeholders with the corresponding copyright year and author name. You'd then be ready to do the open source community a favor and submit your package to [NuGet](https://nuget.org).
* Please note: for NuGet packages you need to include the license in your .csproj in some way. You can for example add the following snippet down below to your class library's .csproj file to have the Apache-2.0 license applied to your NuGet package. It's best if that license matches the one you have added to your repository root directory...

```
<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>
```

Also, don't forget to `git lfs track` binary files that are project-relevant. 
* E.g. `git lfs track "*.png"` to use [Git LFS](https://git-lfs.github.com/) for .png files.
* Edit the .gitignore to your needs
* Replace the [shields](https://shields.io) at the top of this file with your [Circle CI](https://circleci.com) and [Travis CI](https://travis-ci.org) pipeline URLs.

---

# IMPORTANT NOTE
**To clone this template repo correctly, you need to have git lfs installed and set up on your machine!**
