using System.Security.Claims;
using Authentication.Components;
using Authentication.Data;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = IdentityConstants.ApplicationScheme;
        options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
    })
    .AddIdentityCookies();

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<AuthenticationDbContext>(options => options.UseSqlite(connectionString));
builder.Services.AddIdentityCore<ApplicationUser>(options =>
    {
        options.SignIn.RequireConfirmedAccount = false;
        options.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<AuthenticationDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/login";
});

var googleClientId = builder.Configuration["Authentication:Google:ClientId"];
var googleClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
if (!string.IsNullOrWhiteSpace(googleClientId) && !string.IsNullOrWhiteSpace(googleClientSecret))
{
    builder.Services.AddAuthentication()
        .AddGoogle(options =>
        {
            options.ClientId = googleClientId!;
            options.ClientSecret = googleClientSecret!;
        });
}

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>();
    dbContext.Database.Migrate();
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapGet("/auth/google", async (IAuthenticationSchemeProvider schemes) =>
{
    if (await schemes.GetSchemeAsync(GoogleDefaults.AuthenticationScheme) is null)
    {
        return Results.Redirect("/login?externalError=notconfigured");
    }

    return Results.Challenge(
        new AuthenticationProperties { RedirectUri = "/auth/google/callback" },
        [GoogleDefaults.AuthenticationScheme]);
});

app.MapGet("/auth/google/callback", async (
    SignInManager<ApplicationUser> signInManager,
    UserManager<ApplicationUser> userManager) =>
{
    var info = await signInManager.GetExternalLoginInfoAsync();
    if (info is null)
    {
        return Results.Redirect("/login?externalError=failed");
    }

    await signInManager.Context.SignOutAsync(IdentityConstants.ExternalScheme);

    var signInResult = await signInManager.ExternalLoginSignInAsync(
        info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

    if (signInResult.Succeeded)
    {
        return Results.Redirect("/");
    }

    if (signInResult.IsLockedOut)
    {
        return Results.Redirect("/login?externalError=locked");
    }

    var email = info.Principal.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Redirect("/login?externalError=noemail");
    }

    // Do not auto-link Google to an existing password account by email.
    if (await userManager.FindByEmailAsync(email) is not null)
    {
        return Results.Redirect("/login?externalError=emailexists");
    }

    var userName = await GenerateUserNameAsync(userManager, email);
    var user = new ApplicationUser
    {
        UserName = userName,
        Email = email,
        EmailConfirmed = true
    };

    if (!(await userManager.CreateAsync(user)).Succeeded)
    {
        return Results.Redirect("/login?externalError=createfailed");
    }

    if (!(await userManager.AddLoginAsync(user, info)).Succeeded)
    {
        return Results.Redirect("/login?externalError=createfailed");
    }

    await signInManager.SignInAsync(user, isPersistent: false);
    return Results.Redirect("/");
});

app.MapPost("/auth/logout", async (
    HttpContext httpContext,
    SignInManager<ApplicationUser> signInManager,
    IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(httpContext);
    }
    catch (AntiforgeryValidationException)
    {
        return Results.BadRequest("Invalid antiforgery token.");
    }

    await signInManager.SignOutAsync();
    return Results.Redirect("/");
});

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

static async Task<string> GenerateUserNameAsync(UserManager<ApplicationUser> userManager, string email)
{
    var localPart = email.Split('@')[0];
    var baseName = new string(localPart
        .Where(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '+')
        .ToArray());

    if (baseName.Length < 3)
    {
        baseName = "user";
    }

    if (baseName.Length > 32)
    {
        baseName = baseName[..32];
    }

    var candidate = baseName;
    for (var suffix = 1; await userManager.FindByNameAsync(candidate) is not null; suffix++)
    {
        var suffixText = suffix.ToString();
        candidate = baseName[..Math.Min(baseName.Length, 32 - suffixText.Length)] + suffixText;
    }

    return candidate;
}
