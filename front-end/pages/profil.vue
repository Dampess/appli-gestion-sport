<template>
    <div class="container mx-auto px-4 py-8 min-h-screen">
        <h1 class="text-3xl font-bold mb-8">Profil Utilisateur</h1>

        <div class="bg-white rounded-lg shadow-md p-6 mb-2 ">
            <div class="grid grid-cols-2 gap-x-4 gap-y-2 ">
                <div class="col-span-2">
                    <img v-if="user.avatar" :src="user.avatar.data" alt="Avatar"
                        class="w-28 h-28 rounded-full mx-auto mb-4">
                    <div v-else
                        class="w-28 h-28 mb-4 rounded-full bg-gray-300 mx-auto flex items-center justify-center">
                        <span class="text-gray-600 text-4xl"><svg xmlns="http://www.w3.org/2000/svg" width="52"
                                height="52" viewBox="0 0 24 24">
                                <path fill="currentColor"
                                    d="M11.5 14c4.14 0 7.5 1.57 7.5 3.5V20H4v-2.5c0-1.93 3.36-3.5 7.5-3.5m6.5 3.5c0-1.38-2.91-2.5-6.5-2.5S5 16.12 5 17.5V19h13zM11.5 5A3.5 3.5 0 0 1 15 8.5a3.5 3.5 0 0 1-3.5 3.5A3.5 3.5 0 0 1 8 8.5A3.5 3.5 0 0 1 11.5 5m0 1A2.5 2.5 0 0 0 9 8.5a2.5 2.5 0 0 0 2.5 2.5A2.5 2.5 0 0 0 14 8.5A2.5 2.5 0 0 0 11.5 6" />
                            </svg></span>
                    </div>

                    <p class="text-gray-600 mb-2 capitalize"><strong>Nom:</strong> {{ user.name && user.name.data ?
                        user.name.data :
                        'Non Renseigné' }}</p>
                    <p class="text-gray-600 mb-2 capitalize"><strong>Prénom:</strong> {{ user.firstname &&
                        user.firstname.data ?
                        user.firstname.data : 'Non Renseigné' }}</p>
                    <p class="text-gray-600 mb-2"><strong>Email:</strong> {{ user.email && user.email.data ?
                        user.email.data
                        : 'Non Renseigné' }}</p>

                    <p class="text-gray-600 mb-2"><strong>Poids:</strong> {{ user.weight && user.weight.data ?
                        user.weight.data : 'Non Renseigné' }}</p>
                    <p class="text-gray-600 mb-2"><strong>Licence:</strong> {{ user.licence && user.licence.data ?
                        user.licence.data : 'Non Renseigné' }}</p>
                    <p class="text-gray-600 mb-2"><strong>Genre:</strong> {{ user.gender ? 'Homme' : 'Femme' }}</p>

                    <p class="text-gray-600 mb-2"><strong>Téléphone Médical:</strong> {{ user.tel_medic &&
                        user.tel_medic.data ? user.tel_medic.data : 'Non Renseigné' }}</p>
                    <p class="text-gray-600 mb-2"><strong>Téléphone d'urgence:</strong> {{ user.tel_emergency &&
                        user.tel_emergency.data ? user.tel_emergency.data : 'Non Renseigné' }}</p>
                </div>
            </div>
        </div>

        <div class="flex flex-col">
            <!-- Bouton Modifier le profil -->
            <button @click="editProfile" v-if="!isEditing"
                class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded mt-4">
                Modifier le profil
            </button>
            <!-- Bouton Supprimer le profil -->
            <button @click="confirmDelete" v-if="!isEditing"
                class="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded mt-4">
                Supprimer le compte
            </button>

            <!-- Bouton Annuler et Enregistrer les modifications -->
            <div v-if="isEditing" class="bg-white rounded-lg shadow-md p-6 mt-48 mx-4 absolute top-0 left-0 right-0">
                <p>Avatar:</p>
                <input type="file" @change="handleAvatarUpload"
                    class="mb-4 appearance-none bg-white border border-gray-300 rounded-md py-2 text-gray-700 leading-tight focus:outline-none focus:bg-white focus:border-gray-500">

                <p>Poids:</p>
                <input type="text" v-model="editedWeight" placeholder="Nouveau poids" class="input-field mb-4">
                <p>Licence:</p>
                <input type="text" v-model="editedLicence" placeholder="Nouvelle licence" class="input-field mb-4">
                <p>Téléphone médicale:</p>
                <input type="text" v-model="editedTelMedic" placeholder="Nouveau téléphone médical"
                    class="input-field mb-4">
                <p>Téléphone d'urgence:</p>
                <input type="text" v-model="editedTelEmergency" placeholder="Nouveau téléphone d'urgence"
                    class="input-field mb-4">
                <div class="flex justify-center space-x-4">

                    <button @click="saveChanges"
                        class="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 text-center rounded mt-4">
                        Enregistrer les modifications
                    </button>
                    <button @click="cancelEdit"
                        class="bg-red-500 hover:bg-gray-700 text-white font-bold py-2 px-4 text-center rounded mt-4">
                        Annuler
                    </button>
                </div>
            </div>
        </div>
        <button @click="openChangePasswordModal"
            class="bg-yellow-500 w-full hover:bg-yellow-700 text-white font-bold py-2 px-4 rounded mt-4">
            Changer le mot de passe
        </button>

        <!-- Modal de changement de mot de passe -->
        <div v-if="showChangePasswordModal" class="fixed z-10 inset-0 overflow-y-auto">
            <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
                <div class="fixed inset-0 transition-opacity" aria-hidden="true">
                    <div class="absolute inset-0 bg-gray-500 opacity-75"></div>
                </div>
                <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
                <div
                    class="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
                    <div class="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                        <div class="sm:flex sm:items-start">
                            <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left w-full">
                                <h3 class="text-lg leading-6 font-medium text-gray-900">Changer le mot de passe</h3>
                                <div class="mt-2">
                                    <div class="mb-4">
                                        <label for="currentPassword" class="block text-sm font-medium text-gray-700">Mot
                                            de passe actuel</label>
                                        <input type="password" v-model="currentPassword" id="currentPassword"
                                            name="currentPassword" class="input-field">
                                    </div>
                                    <div class="mt-2">
                                        <label for="newPassword" class="block text-sm font-medium text-gray-700">Nouveau
                                            mot de passe</label>
                                        <input type="password" v-model="newPassword" id="newPassword" name="newPassword"
                                            class="input-field">
                                        <!-- Afficher un message d'erreur si le mot de passe ne respecte pas les critères -->
                                        <p v-if="!validatePassword(newPassword)" class="text-red-500 text-xs mt-1">Le
                                            mot de passe doit contenir au moins une lettre majuscule, une lettre
                                            minuscule, un chiffre et un caractère spécial.</p>
                                    </div>
                                    <div>
                                        <label for="confirmNewPassword"
                                            class="block text-sm font-medium text-gray-700">Confirmer le nouveau mot de
                                            passe</label>
                                        <input type="password" v-model="confirmNewPassword" id="confirmNewPassword"
                                            name="confirmNewPassword" class="input-field">
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                        <button @click="changePassword" type="button"
                            class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-500 text-base font-medium text-white hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:ml-3 sm:w-auto sm:text-sm">
                            Changer
                        </button>
                        <button @click="closeChangePasswordModal" type="button"
                            class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm">
                            Annuler
                        </button>
                    </div>
                </div>
            </div>
        </div>


    </div>
</template>

<script>
export default {
    data() {
        return {
            user: {
                name: null,
                firstname: null,
                date_Subscribe: null,
                email: null,
                weight: null,
                licence: null,
                gender: null,
                tel_medic: null,
                tel_emergency: null,
                avatar: null,
                password: null
            },
            isEditing: false,
            editedName: null,
            editedEmail: null,
            editedWeight: null,
            editedLicence: null,
            editedGender: null,
            editedTelMedic: null,
            editedTelEmergency: null,
            avatar: null,
            password: null,
            currentPassword: null,
            newPassword: null,
            confirmNewPassword: null,
            showChangePasswordModal: false,
        };
    },
    async mounted() {
        await this.fetchUserData();
    },
    methods: {
        getUserIdFromToken() {
            const token = localStorage.getItem('accessToken');
            if (!token) {
                console.error('Aucun token trouvé dans le localStorage.');
                return null;
            }

            const tokenParts = token.split('.');
            if (tokenParts.length !== 3) {
                console.error('Le token JWT est invalide.');
                return null;
            }

            const payload = JSON.parse(atob(tokenParts[1]));
            if (!payload || !payload.sub) {
                console.error('Impossible de trouver le champ "sub" dans le token.');
                return null;
            }

            return payload.sub;
        },
        async fetchUserData() {
            try {
                const token = localStorage.getItem('accessToken');
                const userId = this.getUserIdFromToken();
                if (!userId) {
                    console.error('Impossible de récupérer l\'ID de l\'utilisateur.');
                    return;
                }
                const response = await fetch(`http://localhost:8080/users/${userId}`, {
                    method: 'GET',
                    mode: 'cors',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    }
                });
                const data = await response.json();
                this.user = data;
            } catch (error) {
                console.error('Erreur lors de la récupération des informations utilisateur', error);
            }
        },
        editProfile() {
            this.isEditing = true;
            // Initialiser les champs d'entrée avec les valeurs actuelles de l'utilisateur
            this.editedWeight = this.user.weight ? this.user.weight.data : null;
            this.editedLicence = this.user.licence ? this.user.licence.data : null;
            this.editedTelMedic = this.user.tel_medic ? this.user.tel_medic.data : null;
            this.editedTelEmergency = this.user.tel_emergency ? this.user.tel_emergency.data : null;
        },
        async saveChanges() {
            this.user.weight = this.editedWeight;
            this.user.licence = this.editedLicence;
            this.user.tel_medic = this.editedTelMedic;
            this.user.tel_emergency = this.editedTelEmergency;
            this.user.password = null;
            this.user.name = null;
            this.user.firstname = null;
            this.user.date_end_pay = null;
            this.user.date_payment = null;

            
            try {
                const token = localStorage.getItem('accessToken');
                const userId = this.getUserIdFromToken();
                if (!userId) {
                    console.error('Impossible de récupérer l\'ID de l\'utilisateur.');
                    return;
                }
                
                await useFetch(`http://localhost:8080/users/${userId}`, {
                    method: 'PATCH',
                    mode: 'cors',
                    body: JSON.stringify(this.user),
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    }
                });
                this.isEditing = false;
                this.editedName = null;
                this.editedEmail = null;
                this.editedWeight = null;
                this.editedLicence = null;
                this.editedGender = null;
                this.editedTelMedic = null;
                this.editedTelEmergency = null;

                document.location.href = "/profil"
            } catch (error) {
                console.error('Erreur lors de la sauvegarde des modifications', error);
            }
        },
        cancelEdit() {
            this.isEditing = false;
        },
        confirmDelete() {
            if (confirm("Êtes-vous sûr de vouloir supprimer votre compte ?")) {
                this.deleteUser();
            }
        },
        async deleteUser() {
            try {
                const token = localStorage.getItem('accessToken');
                const userId = this.getUserIdFromToken();
                if (!userId) {
                    console.error('Impossible de récupérer l\'ID de l\'utilisateur.');
                    return;
                }
                await useFetch(`http://localhost:8080/users/${userId}`, {
                    method: 'DELETE',
                    mode: 'cors',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    }
                });
                // Rediriger l'utilisateur vers la page d'accueil après la suppression si nécessaire
                this.$router.push('/');
            } catch (error) {
                console.error('Erreur lors de la suppression de l\'utilisateur', error);
            }
        },
        async handleAvatarUpload(event) {
            const file = event.target.files[0];
            if (file) {
                // Si un fichier est sélectionné, procédez comme d'habitude pour mettre à jour l'avatar
                const token = localStorage.getItem('accessToken');
                const userId = this.getUserIdFromToken();
                if (!userId) {
                    console.error('Impossible de récupérer l\'ID de l\'utilisateur.');
                    return;
                }
                const formData = new FormData();
                formData.append('avatar', file); // Ajoutez le fichier à FormData sous la clé 'avatar'
                try {
                    const response = await fetch(`http://localhost:8080/users/${userId}`, {
                        method: 'PATCH',
                        mode: 'cors',
                        body: formData, // Utilisez le FormData comme corps de la requête
                        headers: {
                            'Authorization': `Bearer ${token}`
                        }
                    });
                    if (response.ok) {
                        // Convertir le fichier en URL de données (data URL)
                        const reader = new FileReader();
                        reader.onload = () => {
                            // Mettre à jour l'URL de l'avatar dans l'interface utilisateur
                            this.user.avatar = reader.result;
                        };
                        reader.readAsDataURL(file);

                        // Stockez également le fichier pour le télécharger plus tard si nécessaire
                        this.avatar = file;
                    } else {
                        console.error('Erreur lors du téléchargement de la photo de profil:', response.status);
                    }
                } catch (error) {
                    console.error('Erreur lors du téléchargement de la photo de profil:', error);
                }
            } else {
                // Si aucun fichier n'est sélectionné, ne rien faire
                console.log('Aucun fichier sélectionné pour l\'avatar.');
            }
        },
        openChangePasswordModal() {
            this.showChangePasswordModal = true;
        },
        closeChangePasswordModal() {
            this.showChangePasswordModal = false;
            // Réinitialiser les champs de mot de passe lorsque la modal est fermée
            this.currentPassword = '';
            this.newPassword = '';
            this.confirmNewPassword = '';
        },
        async changePassword() {
            
            // Vérifier si les nouveaux mots de passe correspondent
            if (this.newPassword !== this.confirmNewPassword) {
                alert("Les nouveaux mots de passe ne correspondent pas.");
                return;
            }

            try {
                // Envoyer une requête au serveur pour changer le mot de passe
                const token = localStorage.getItem('accessToken');
                const userId = this.getUserIdFromToken();
                if (!userId) {
                    console.error('Impossible de récupérer l\'ID de l\'utilisateur.');
                    return;
                }
                const response = await fetch(`http://localhost:8080/users/${userId}/`, {
                    method: 'PATCH',
                    mode: 'cors',
                    body: JSON.stringify({
                        currentPassword: this.currentPassword,
                        password: this.newPassword
                    }),
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    }
                });
                if (response.ok) {
                    alert("Mot de passe changé avec succès.");
                    this.closeChangePasswordModal();
                } else {
                    const errorMessage = await response.text();
                    alert(`Erreur lors du changement de mot de passe : ${errorMessage}`);
                }
            } catch (error) {
                console.error('Erreur lors du changement de mot de passe', error);
                alert("Erreur lors du changement de mot de passe. Veuillez réessayer.");
            }
        },
        validatePassword(password) {
            // Expression régulière pour valider le mot de passe
            const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
            return passwordRegex.test(password);
        },

    }


};
</script>

<style>
.input-field {
    border: 1px solid #e2e8f0;
    padding: 8px;
    width: 100%;
}
</style>
