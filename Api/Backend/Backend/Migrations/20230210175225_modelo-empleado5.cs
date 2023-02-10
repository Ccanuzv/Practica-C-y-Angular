using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Backend.Migrations
{
    /// <inheritdoc />
    public partial class modeloempleado5 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "EmpleadoPDI",
                table: "Empleados",
                newName: "EmpleadoDPI");

            migrationBuilder.RenameColumn(
                name: "EmpleadoFechaCreación",
                table: "Empleados",
                newName: "EmpleadoFechaCreacion");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "EmpleadoFechaCreacion",
                table: "Empleados",
                newName: "EmpleadoFechaCreación");

            migrationBuilder.RenameColumn(
                name: "EmpleadoDPI",
                table: "Empleados",
                newName: "EmpleadoPDI");
        }
    }
}
