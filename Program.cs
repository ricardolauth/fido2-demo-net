using System.Security.Claims;
using System.Text;
using fido2_demo.Authorization;
using fido2_demo.Model;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<FidoDemoContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("Database")));

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo { Title = "Fido Demo API", Version = "v1" });
    option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter a valid token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });
    option.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type=ReferenceType.SecurityScheme,
                    Id="Bearer"
                }
            },
            new string[]{}
        }
    });
});

// Use the in-memory implementation of IDistributedCache.
builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();

builder.Services.AddApplicationInsightsTelemetry();

// Custom Services
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddTransient<IJwtUtils, JwtUtils>();

builder.Services
    .AddAuthentication()
    .AddJwtBearer(option =>
    {


        option.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["secret"]!)),
            ValidateIssuer = false,
            ValidateAudience = false,
            // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
            ClockSkew = TimeSpan.Zero,
            NameClaimType = ClaimTypes.Actor,
        };

        JwtBearerEvents events = new()
        {
            OnTokenValidated = async context =>
            {
                var db = context.HttpContext.RequestServices.GetService<FidoDemoContext>();

                // Find claim identity attached to principal.
                var claimIdentity = (ClaimsIdentity?)context.Principal?.Identity;

                // Find actor from claims list.
                var actor =
                    claimIdentity?.Claims.Where(x => x.Type.Equals(ClaimTypes.Actor))
                        .Select(x => x.Value)
                        .FirstOrDefault();

                // try to parse the actor claim (userId)
                if (!Guid.TryParse(actor, out var userId))
                {
                    context.Fail("Can't parse claim");
                    return;
                }

                // Find the user in the database.
                var userExists = await db!.Users.AsNoTracking().AnyAsync(x => x.Id == userId);
                if (!userExists)
                {
                    context.Fail("User dosn't in the database");
                    return;
                }

                context.Success();
            }
        };

        option.Events = events;

        option.SaveToken = true;
    });

builder.Services.AddAuthorization();

// Add Fido2
builder.Services.AddFido2(options =>
{
    options.ServerDomain = builder.Configuration["fido2:serverDomain"];
    options.ServerName = "FIDO2 Test";
    options.Origins = builder.Configuration.GetSection("fido2:origins").Get<HashSet<string>>();
    options.TimestampDriftTolerance = builder.Configuration.GetValue<int>("fido2:timestampDriftTolerance");
})
.AddCachedMetadataService(config =>
{
    config.AddFidoMetadataRepository(httpClientBuilder =>
    {
        //TODO: any specific config you want for accessing the MDS
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    // Allow CORS in development
    app.UseCors(p => p.AllowAnyMethod().AllowAnyOrigin().AllowAnyHeader());
}

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Fido 2 RP Demo");
});

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();