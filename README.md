[![AppVeyor](https://ci.appveyor.com/api/projects/status/jbj097s3ik1y3hwp/branch/master?svg=true)](https://ci.appveyor.com/project/GlitchedPolygons/cryptography-symmetric/branch/master) [![Travis](https://travis-ci.org/GlitchedPolygons/Cryptography.Symmetric.svg?branch=master)](https://travis-ci.org/GlitchedPolygons/Cryptography.Symmetric) [![CircleCI](https://circleci.com/gh/GlitchedPolygons/Cryptography.Symmetric.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/Cryptography.Symmetric) 

# Symmetric Cryptography

## Encrypting and decrypting data made easy.

#### Namespace:  `GlitchedPolygons.Services.Cryptography.Symmetric`

This is a simple, easy-to-use crypto library for C# ([netstandard2.0](https://github.com/dotnet/standard/blob/master/docs/versions/netstandard2.0.md)).

You can encrypt and decrypt `string` and `byte[]` arrays with ease. The interfaces and their implementations are also IoC friendly, so you can inject them into your favorite DI containers (e.g. in [ASP.NET Core MVC](https://docs.microsoft.com/en-us/aspnet/core/mvc/overview?view=aspnetcore-2.2) apps you'd use `services.AddTransient` inside _Startup.cs_).

The `ISymmetricCryptography` interface provides functionality for all basic symmetric crypto operations you need for your C# project. 
For more information, check out the [API Documentation](https://glitchedpolygons.github.io/Cryptography.Symmetric/api/GlitchedPolygons.Services.Cryptography.Symmetric.html).

**Technology used:**
* C# ([netstandard2.0](https://github.com/dotnet/standard/blob/master/docs/versions/netstandard2.0.md))

---

API docs can be found here:
_[glitchedpolygons.github.io/Cryptography.Symmetric](https://glitchedpolygons.github.io/Cryptography.Symmetric/api/GlitchedPolygons.Services.Cryptography.Symmetric.html)_
