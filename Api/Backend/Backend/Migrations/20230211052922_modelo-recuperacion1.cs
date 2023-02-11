using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Backend.Migrations
{
    /// <inheritdoc />
    public partial class modelorecuperacion1 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Recuperaciones",
                columns: table => new
                {
                    RecuperacionId = table.Column<string>(type: "text", nullable: false),
                    RecuperacionEstado = table.Column<bool>(type: "boolean", nullable: false),
                    RecuperacionFechaCreacion = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RecuperacionUsuarioId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Recuperaciones", x => x.RecuperacionId);
                    table.ForeignKey(
                        name: "FK_Recuperaciones_Usuarios_RecuperacionUsuarioId",
                        column: x => x.RecuperacionUsuarioId,
                        principalTable: "Usuarios",
                        principalColumn: "UsuarioId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Recuperaciones_RecuperacionUsuarioId",
                table: "Recuperaciones",
                column: "RecuperacionUsuarioId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Recuperaciones");
        }
    }
}
