<template>
    <div class="flex justify-between items-center p-4 bg-white text-white border-b-2 border-gray-400">

        <h1 class="text-2xl text-black font-bold">MMA Baisieux</h1>

        <div v-if="isAuthenticated">
            <!-- Menu déroulant -->
            <div class="relative">
                <button @click="toggleMenu" class="flex items-center">
                    <!-- Icône de menu (à remplacer par votre propre icône) -->
                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24">
                        <path fill="bg-black"
                            d="M19 18v-4h-2v4h-2l3 3l3-3zM11 4C8.8 4 7 5.8 7 8s1.8 4 4 4s4-1.8 4-4s-1.8-4-4-4m0 10c-4.4 0-8 1.8-8 4v2h9.5c-.3-.8-.5-1.6-.5-2.5c0-1.2.3-2.3.9-3.4c-.6 0-1.2-.1-1.9-.1" />
                    </svg>
                </button>
                <!-- Contenu du menu déroulant -->
                <div v-show="isMenuOpen" class="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg z-10">
                    <NuxtLink class="block px-4 py-2 text-gray-800 hover:bg-gray-200 cursor-pointer" to="/profil">
                        Profil
                    </NuxtLink>
                    <NuxtLink class="block px-4 py-2 text-gray-800 hover:bg-gray-200 cursor-pointer" to="/">
                        Accueil
                    </NuxtLink>
                    <!-- Affichage de la page d'administration pour les utilisateurs avec un rôle spécifique -->
                    <div v-if="userRole === 1 || userRole === 2">
                        <NuxtLink class="block px-4 py-2 text-gray-800 hover:bg-gray-200 cursor-pointer" to="/admin">
                            Administration
                        </NuxtLink>
                    </div>
                    <button @click="logout" class=" block px-4 py-2 text-gray-800 hover:bg-gray-200 cursor-pointer">
                        Déconnexion
                    </button>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
export default {
    name: "Header",
    data() {
        return {
            isAuthenticated: false,
            userRole: 0,
            isMenuOpen: false
        };
    },
    created() {
        this.checkAuthentication();
    },
    methods: {
        checkAuthentication() {
            const accessToken = localStorage.getItem('accessToken');
            if (accessToken) {
                this.isAuthenticated = true;
                this.checkUserRole();
            } else {
                this.isAuthenticated = false;
            }
        },
        checkUserRole() {
            const accessToken = localStorage.getItem('accessToken');
            if (accessToken) {
                const decodedToken = JSON.parse(atob(accessToken.split('.')[1]));
                this.userRole = decodedToken.role;
            } else {
                this.userRole = 0;
            }
        },
        logout() {
            localStorage.removeItem('accessToken');
            document.location.href = "/";
        },
        toggleMenu() {
            this.isMenuOpen = !this.isMenuOpen;
        }
    }
};
</script>
