// <auto-generated />
using System;
using Backend.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Backend.Migrations
{
    [DbContext(typeof(PracticaDB))]
    [Migration("20230210164528_modelo-usuario1")]
    partial class modelousuario1
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "7.0.2")
                .HasAnnotation("Relational:MaxIdentifierLength", 63);

            NpgsqlModelBuilderExtensions.UseIdentityByDefaultColumns(modelBuilder);

            modelBuilder.Entity("Backend.Modelo.Entity.Usuario", b =>
                {
                    b.Property<string>("UsuarioId")
                        .HasColumnType("text");

                    b.Property<string>("UsuarioEmail")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<DateTime>("UsuarioFechaNacimiento")
                        .HasColumnType("timestamp with time zone");

                    b.Property<string>("UsuarioNombre")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<string>("UsuarioPass")
                        .IsRequired()
                        .HasColumnType("text");

                    b.HasKey("UsuarioId");

                    b.ToTable("Usuarios");
                });
#pragma warning restore 612, 618
        }
    }
}
