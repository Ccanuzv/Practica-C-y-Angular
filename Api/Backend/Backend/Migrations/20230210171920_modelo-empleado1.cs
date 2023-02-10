using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Backend.Migrations
{
    /// <inheritdoc />
    public partial class modeloempleado1 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Empleados",
                columns: table => new
                {
                    EmpleadoId = table.Column<string>(type: "text", nullable: false),
                    EmpleadoNombre = table.Column<string>(type: "text", nullable: false),
                    EmpleadoPDI = table.Column<string>(type: "text", nullable: false),
                    EmpleadoCantidadHijos = table.Column<int>(type: "integer", nullable: false),
                    EmpleadoSalario = table.Column<float>(type: "real", nullable: false),
                    EmpleadoBonoDecreto = table.Column<float>(type: "real", nullable: false),
                    EmpleadoFechaCreación = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    EmpleadoUsuarioId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Empleados", x => x.EmpleadoId);
                    table.ForeignKey(
                        name: "FK_Empleados_Usuarios_EmpleadoUsuarioId",
                        column: x => x.EmpleadoUsuarioId,
                        principalTable: "Usuarios",
                        principalColumn: "UsuarioId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Empleados_EmpleadoUsuarioId",
                table: "Empleados",
                column: "EmpleadoUsuarioId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Empleados");
        }
    }
}
