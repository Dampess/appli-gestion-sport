<template>
    <div class="container mx-auto py-8">
        <h1 class="text-3xl ml-2 font-semibold mb-4">Administration</h1>
        <div class="mb-8 bg-white mx-2 rounded p-2" style="overflow-x: auto;">
            <h2 class="text-xl font-semibold mb-2">Utilisateurs inactifs</h2>
            <div class="overflow-x-auto">
                <table class="mx-auto min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th scope="col"
                                class="px-3 py-1 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Nom
                            </th>
                            <th scope="col"
                                class="px-3 py-1 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Prénom
                            </th>
                            <th scope="col"
                                class="px-3 py-1 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Actions
                            </th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <tr v-for="(user, index) in inactiveUsers" :key="user.id">
                            <td class="px-3 py-2 whitespace-nowrap text-sm text-gray-500 capitalize">
                                {{ user.name.data }}
                            </td>
                            <td class="px-3 py-2 whitespace-nowrap text-sm text-gray-500 capitalize">
                                {{ user.firstname.data }}
                            </td>
                            <td class="px-3 py-2 whitespace-nowrap text-sm text-gray-500">
                                <button @click="reactivateUser(user)"
                                    class="bg-blue-500 text-white px-4 py-1 rounded-md hover:bg-blue-600">Activer</button>

                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Liste des utilisateurs -->
        <div class="mb-8 bg-white mx-2 rounded p-2" style="overflow-x: auto;">
            <h2 class="text-xl font-semibold mb-2">Liste des utilisateurs</h2>
            <div class="flex items-center space-x-4 mb-4">
                <select @change="updateSortBy(value)">
                    <option value="">Trier par...</option>
                    <option value="age">Âge</option>
                    <option value="gender">Genre</option>
                    <option value="weight">Poids</option>
                    <!-- Ajoutez d'autres options de tri ici -->
                </select>
                <select @change="updateSortOrder(value)">
                    <option value="">Trier par...</option>
                    <option value="asc">Croissant</option>
                    <option value="desc">Décroissant</option>
                </select>
                <button @click="handleSort"> Filtrer</button>
            </div>

            <div class="overflow-x-auto">
                <table class="mx-auto min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th scope="col"
                                class="px-3 py-1 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Statut <!-- Ajoutez l'icône pour le statut ici -->
                            </th>

                            <th scope="col"
                                class="px-3 py-1 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Nom
                            </th>
                            <th scope="col"
                                class="px-3 py-1 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Prénom
                            </th>
                            <th scope="col"
                                class="px-3 py-1 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Actions
                            </th>

                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <tr v-for="(user, index) in users" :key="user.id" :class="{
                            'bg-orange-600': (!user.licence || !user.date_end_pay || new Date(user.date_end_pay) < new Date()),
                            'bg-red-600': (!user.licence && (!user.date_end_pay || new Date(user.date_end_pay) < new Date())),
                            'bg-white': (user.licence && (!user.date_end_pay || new Date(user.date_end_pay) >= new Date()))
                        }">
                            <td class="px-3 py-2 whitespace-nowrap text-sm text-gray-500">
                                <!-- Icône pour le statut -->
                                <span>
                                    <!-- Icône de billet si la date d'expiration est < à aujourd'hui ou null -->
                                    <svg v-if="!user.date_end_pay || new Date(user.date_end_pay) < new Date()"
                                        xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 256 256">
                                        <g fill="text-black">
                                            <path
                                                d="M160 128a32 32 0 1 1-32-32a32 32 0 0 1 32 32m40-64a48.85 48.85 0 0 0 40 40V64Zm0 128h40v-40a48.85 48.85 0 0 0-40 40M16 152v40h40a48.85 48.85 0 0 0-40-40m0-48a48.85 48.85 0 0 0 40-40H16Z"
                                                opacity=".2" />
                                            <path
                                                d="M128 88a40 40 0 1 0 40 40a40 40 0 0 0-40-40m0 64a24 24 0 1 1 24-24a24 24 0 0 1-24 24m112-96H16a8 8 0 0 0-8 8v128a8 8 0 0 0 8 8h224a8 8 0 0 0 8-8V64a8 8 0 0 0-8-8M24 72h21.37A40.81 40.81 0 0 1 24 93.37Zm0 112v-21.37A40.81 40.81 0 0 1 45.37 184Zm208 0h-21.37A40.81 40.81 0 0 1 232 162.63Zm0-38.35A56.78 56.78 0 0 0 193.65 184H62.35A56.78 56.78 0 0 0 24 145.65v-35.3A56.78 56.78 0 0 0 62.35 72h131.3A56.78 56.78 0 0 0 232 110.35Zm0-52.28A40.81 40.81 0 0 1 210.63 72H232Z" />
                                        </g>

                                    </svg>
                                    <!-- Icône de carte d'identité si la licence est null -->
                                    <svg v-if="!user.licence" xmlns="http://www.w3.org/2000/svg" width="32" height="32"
                                        viewBox="0 0 24 24">
                                        <path fill="text-black"
                                            d="M14 13h5v-2h-5zm0-3h5V8h-5zm-9 6h8v-.55q0-1.125-1.1-1.787T9 13q-1.8 0-2.9.663T5 15.45zm4-4q.825 0 1.413-.587T11 10q0-.825-.587-1.412T9 8q-.825 0-1.412.588T7 10q0 .825.588 1.413T9 12m-5 8q-.825 0-1.412-.587T2 18V6q0-.825.588-1.412T4 4h16q.825 0 1.413.588T22 6v12q0 .825-.587 1.413T20 20zm0-2h16V6H4zm0 0V6z" />
                                    </svg>
                                </span>
                            </td>

                            <td class="px-3 py-2 whitespace-nowrap text-sm text-black font-semibold capitalize">
                                {{ user.name.data }}
                            </td>
                            <td class="px-3 py-2 whitespace-nowrap text-sm text-black font-semibold capitalize">
                                {{ user.firstname.data }}
                            </td>
                            <td class="px-3 py-2 whitespace-nowrap text-sm font-semibold text-gray-500">
                                <!-- Bouton pour ouvrir la modale -->
                                <button @click="openModal(user)" class="focus:outline-none text-black">
                                    <!-- Icône de flèche vers le bas -->
                                    <svg xmlns="http://www.w3.org/2000/svg"
                                        class="h-5 w-5 text-black hover:text-gray-600 transition duration-300"
                                        viewBox="0 0 20 20" fill="currentColor">
                                        <path fill-rule="evenodd" d="M10 12l-6-6h12l-6 6z" clip-rule="evenodd" />
                                    </svg>
                                </button>


                            </td>

                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        <!-- Création de cours  -->
        <div class="bg-white mx-2 rounded p-2">
            <h2 class="text-xl font-semibold mb-2">Créer un nouveau cours</h2>
            <form @submit.prevent="createCourse" class="flex flex-col space-y-4">
                <div class="flex flex-col">
                    <label for="title" class="font-semibold">Titre du cours</label>
                    <input type="text" v-model="newCourse.name_event" id="title"
                        class="border border-gray-300 bg-gray-200 px-4 py-2 rounded-md">
                </div>
                <div class="flex flex-col">
                    <label for="description" class="font-semibold">Description du cours</label>
                    <textarea v-model="newCourse.overview" id="description"
                        class="border border-gray-300 bg-gray-200 px-4 py-2 rounded-md" placeholder=""></textarea>
                </div>
                <div class="flex flex-col">
                    <label for="date">Date et heure de début</label>
                    <input type="datetime-local" v-model="newCourse.date_event" id="date"
                        class="border border-gray-300 bg-gray-200 px-4 py-2 rounded-md">
                </div>
                <div class="flex flex-col">
                    <label for="coach">Nom du coach</label>
                    <input type="text" v-model="newCourse.coach" id="coach"
                        class="border border-gray-300 bg-gray-200 px-4 py-2 rounded-md">
                </div>
                <div class="flex flex-col">
                    <label for="duration">Durée du cours (en minutes)</label>
                    <input type="number" v-model="durationInHours" id="duration"
                        class="border border-gray-300 bg-gray-200 px-4 py-2 rounded-md">
                </div>
                <!-- Champ pour le nombre de places total disponibles -->
                <div class="flex flex-col">
                    <label for="totalSeats">Nombre de places total disponibles</label>
                    <input type="number" v-model="newCourse.totalPlaces" id="totalSeats"
                        class="border border-gray-300 bg-gray-200 px-4 py-2 rounded-md">
                </div>
                <button type="submit" class="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600">Créer le
                    cours</button>
            </form>
        </div>

    </div>
    <!-- Modale Utilisateur  -->
    <div v-if="selectedUser"
        class="fixed inset-0 z-50 overflow-auto bg-black bg-opacity-50 flex items-center justify-center">
        <div class="bg-white rounded-lg p-6 max-w-lg w-full">
            <h2 class="text-xl font-semibold mb-4">Informations de l'utilisateur</h2>
            <div class="flex flex-col space-y-4">
                <!-- Affichage des informations de l'utilisateur -->
                <div>
                    <div>
                        <div>
                            <label for="username"><strong>Nom:</strong></label>
                            <input type="text" v-model="selectedUser.name.data" id="username">
                        </div>
                        <div>
                            <label for="userfirstname"><strong>Prénom:</strong></label>
                            <input type="text" v-model="selectedUser.firstname.data" id="userfirstname">
                        </div>
                        <!-- Autres informations de l'utilisateur -->
                    </div>
                    <p><strong>E-mail:</strong> {{ selectedUser.email.data }}</p>
                    <p><strong>Date de naissance:</strong> {{ formatDate(selectedUser.birthday.data) }}</p>
                    <p><strong>Genre:</strong> {{ selectedUser.gender ? 'Homme' : 'Femme' }}</p>
                    <p><strong>Poids:</strong> {{ selectedUser.weight && selectedUser.weight.data + 'Kg' || 'Non renseigné' }}</p>
                    <p><strong>Téléphone médical:</strong> {{ selectedUser.tel_medic && selectedUser.tel_medic.data ||
                        'Non renseigné' }}</p>
                    <p><strong>Téléphone d'urgence:</strong> {{ selectedUser.tel_emergency &&
                        selectedUser.tel_emergency.data || 'Non renseigné' }}</p>
                    <!-- Ajout des champs pour modifier les dates -->
                    <div>
                        <label for="datePayment"><strong>Date de paiement:</strong></label>
                        <input type="date" v-model="selectedUser.date_payment" id="datePayment">
                        <span v-if="!selectedUser.date_payment">Aucun paiement en cours</span>
                    </div>
                    <div>
                        <label for="dateEndPay"><strong> Date de fin de paiement:</strong></label>
                        <input type="date" v-model="selectedUser.date_end_pay" id="dateEndPay">
                        <span v-if="!selectedUser.date_end_pay">Aucun paiement en cours</span>
                    </div>
                </div>
                <!-- Boutons pour soumettre les modifications et fermer la modal -->
                <div class="flex justify-between">
                    <button @click="updateUser"
                        class="bg-green-500 text-white px-4 py-2 rounded-md hover:bg-green-600">Enregistrer</button>
                    <div v-if="getUserRole() === 2">
                        <button v-if="selectedUser.role === 0" @click="changeUserRole(selectedUser.id)"
                            class="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600">Passer Admin</button>
                    </div>
                    <button @click="closeModalUser"
                        class="bg-red-500 text-white px-4 py-2 rounded-md hover:bg-blue-600">Fermer</button>
                </div>
            </div>
        </div>
    </div>
    <!-- Tableau des événements -->
    <div class="mb-8 bg-white mx-2 rounded p-2 overflow-x-auto">
        <h2 class="text-xl font-semibold mb-2">Liste des événements</h2>
        <div class="max-w-screen-lg mx-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th scope="col"
                            class="px-3 py-1 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Date
                        </th>
                        <th scope="col"
                            class="px-3 py-1 text-left max-w-2 text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Intitulé
                        </th>
                        <th scope="col"
                            class="px-3 py-1 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Actions
                        </th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    <tr v-for="(event, index) in events" :key="event.id">
                        <td class="px-3 py-2 whitespace-nowrap text-sm text-gray-500 capitalize">
                            {{ formatDate(event.date_event) }}
                        </td>
                        <td class="px-3 py-2 max-w-20 whitespace-nowrap text-sm text-gray-500 uppercase">
                            {{ event.name_event }}
                        </td>
                        <td class="flex flex-col px-3 py-2 whitespace-nowrap text-sm font-semibold text-gray-500">
                            <!-- Boutons pour modifier et supprimer l'événement -->
                            <button @click="editEvent(event)"
                                class="bg-blue-500 mb-1 text-white px-4 py-1 rounded-md hover:bg-blue-600">Modifier</button>
                            <button @click="deleteEvent(event.id)"
                                class="bg-red-500 text-white px-4 py-1 rounded-md hover:bg-red-600">Supprimer</button>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
    <!-- Modale pour l'édition de l'événement -->
    <div v-if="showModal" class="fixed z-10 inset-0 overflow-y-auto">
        <div class="flex items-center justify-center min-h-screen px-4">

            <!-- Fond semi-transparent -->
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" aria-hidden="true"></div>

            <!-- Conteneur de la modale -->
            <div class="bg-white rounded-lg overflow-hidden shadow-xl transform transition-all sm:max-w-lg w-full">
                <!-- Contenu de la modale -->
                <div class="px-6 py-4">
                    <!-- Titre de la modale -->
                    <h2 class="text-lg font-medium text-gray-900">Modifier l'événement</h2>

                    <!-- Formulaire pour l'édition de l'événement -->
                    <form @submit.prevent="saveChanges(editedEvent.id)" data-event-id="editedEvent.id">

                        <div class="flex flex-col">
                            <label for="title" class="font-semibold">Titre du cours</label>
                            <input type="text" v-model="editedEvent.name_event" id="title"
                                class="border border-gray-300 bg-gray-200 px-4 py-2 rounded-md">
                        </div>
                        <div class="flex flex-col">
                            <label for="description" class="font-semibold">Description du cours</label>
                            <textarea v-model="editedEvent.overview" id="description"
                                class="border border-gray-300 bg-gray-200 px-4 py-2 rounded-md"
                                placeholder=""></textarea>
                        </div>
                        <div class="flex flex-col">
                            <label for="coach">Nom du coach</label>
                            <input type="text" v-model="editedEvent.coach" id="coach"
                                class="border border-gray-300 bg-gray-200 px-4 py-2 rounded-md">
                        </div>
                        <div class="flex flex-col">
                            <label for="duration">Durée du cours (en minutes)</label>
                            <input type="number" v-model="durationInHours" id="duration"
                                class="border border-gray-300 bg-gray-200 px-4 py-2 rounded-md">
                        </div>
                        <!-- Champ pour le nombre de places total disponibles -->
                        <div class="flex flex-col">
                            <label for="totalSeats">Nombre de places total disponibles</label>
                            <input type="number" v-model="editedEvent.totalPlaces" id="totalSeats"
                                class="border border-gray-300 bg-gray-200 px-4 py-2 rounded-md">
                        </div>



                        <!-- Boutons pour annuler ou sauvegarder -->
                        <div class="flex justify-end">
                            <button type="button" @click="closeModal"
                                class="mr-2 bg-gray-200 text-gray-800 px-4 py-1 rounded-md hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-500">
                                Annuler
                            </button>
                            <button type="submit"
                                class="bg-green-500 text-white px-4 py-1 rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
                                Sauvegarder
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</template>
<script>
export default {
    data() {
        return {
            users: [], // Liste des utilisateurs
            newCourse: { // Nouveau cours à créer
                name_event: null,
                overview: null,
                coach: null,
                date_event: null,
                duration: 0,
                totalPlaces: null,
                places: null
            },
            selectedUser: null,
            inactiveUsers: [],
            events: [],
            showModal: false, // Indicateur pour afficher ou masquer la modale
            editedEvent: {},
            sortBy: null, 
            sortOrder: null

        };
    },
    async mounted() {
        // Charger les événements depuis votre API lors du montage du composant
        await this.loadEvents();
        await this.loadUsers();
        await this.loadInactiveUsers();

    },
    computed: {
        durationInHours: {
            get() {
                // Renvoie la valeur de newCourse.duration divisée par 60
                return this.newCourse.duration / 60;
            },
            set(value) {
                // Met à jour newCourse.duration avec la valeur entrée multipliée par 60
                this.newCourse.duration = value * 60;
            }
        }
    },
    methods: {
        async loadEvents() {
            try {
                const token = localStorage.getItem('accessToken');
                // Faire une requête GET à votre API pour récupérer les événements
                const response = await useFetch('http://localhost:8080/events', {
                    method: 'GET',
                    mode: 'cors',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    }
                });

                // Stocker les événements dans la variable events
                this.events = response.data;
            } catch (error) {
                console.error('Erreur lors du chargement des événements', error);
            }
        },
        async createCourse() {
            try {

                this.newCourse.places = this.newCourse.totalPlaces
                const duration = this.newCourse.duration * 60

                const token = localStorage.getItem('accessToken');
                // Envoyer une requête HTTP POST pour créer le cours
                const response = await fetch('http://localhost:8080/events', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify(this.newCourse)
                });

                // Vérifier si la requête a réussi (statut 200)
                if (response.ok) {
                    // Réinitialiser le formulaire après la création réussie
                    this.newCourse = { title: '', description: '', totalSeats: '', date_event: '', coach: '', duration: '' };
                    // Afficher un message de succès à l'utilisateur
                    alert('Le cours a été créé avec succès!');
                } else {
                    // En cas d'erreur, afficher un message d'erreur
                    throw new Error('Erreur lors de la création du cours');
                }
            } catch (error) {
                console.error('Erreur lors de la création du cours:', error);
                // Vous pouvez également afficher un message d'erreur à l'utilisateur ici
            }
        },
        async loadUsers() {
            try {
                const token = localStorage.getItem('accessToken');
                // Faire une requête GET à votre API pour récupérer les utilisateurs
                const response = await useFetch('http://localhost:8080/users', {
                    method: 'GET',
                    mode: 'cors',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    }
                });

                // Stocker les utilisateurs dans la variable users
                this.users = response.data;
            } catch (error) {
                console.error('Erreur lors du chargement des utilisateurs', error);
            }
        },
        // Méthode pour ouvrir la modal et afficher les informations de l'utilisateur sélectionné
        openModal(user) {
            this.selectedUser = user;

        },
        // Méthode pour fermer la modal
        closeModalUser() {
            this.selectedUser = null;
        },
        
        formatDate(dateString) {
            // Convertir la chaîne de caractères de la date en objet Date
            const date = new Date(dateString);

            // Formater la date au format "jour semaine, jour mois année"
            const options = {
                weekday: 'long',
                year: 'numeric',
                month: 'long',
                day: 'numeric'
            };

            let formattedDate = date.toLocaleDateString('fr-FR', options);

            // Extraire les deux derniers chiffres de l'année
            const lastTwoDigitsOfYear = formattedDate.slice(-2);

            // Retirer l'année complète et ajouter les deux derniers chiffres
            formattedDate = formattedDate.replace(date.getFullYear(), lastTwoDigitsOfYear);

            return formattedDate;
        },
        async updateUser() {
            try {
                if (!this.selectedUser) {
                    console.error("Aucun utilisateur sélectionné.");
                    return;
                }

                const token = localStorage.getItem('accessToken');
                const userId = this.selectedUser.id; // Récupérez l'ID de l'utilisateur sélectionné
                this.selectedUser.password = null;


                // Faire une requête HTTP PATCH pour mettre à jour les informations de l'utilisateur
                const response = await useFetch(`http://localhost:8080/users/${userId}`, {
                    method: 'PATCH',
                    mode: 'cors',
                    body: JSON.stringify({
                        name: this.selectedUser.name.data,
                        firstname: this.selectedUser.firstname.data,
                        date_end_pay: this.selectedUser.date_end_pay,
                        date_payment: this.selectedUser.date_payment
                    }),
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                });

                // Vérifiez la réponse de la requête et affichez un message de succès si nécessaire
                console.log('Mise à jour réussie :', response);
            } catch (error) {
                console.error('Erreur lors de la mise à jour de l\'utilisateur', error);
                // Affichez un message d'erreur si la mise à jour échoue
            }
        },

        async loadInactiveUsers() {
            try {
                const token = localStorage.getItem('accessToken');
                // Faire une requête GET à votre API pour récupérer tous les utilisateurs
                const response = await fetch('http://localhost:8080/users', {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    }
                });

                // Vérifiez si la réponse est OK (statut 200)
                if (response.ok) {
                    // Convertissez la réponse en JSON
                    const allUsers = await response.json();
                    // Filtrer les utilisateurs inactifs
                    this.inactiveUsers = allUsers.filter(user => user.isActive === false);
                } else {
                    // En cas d'erreur de réponse, affichez un message d'erreur
                    throw new Error('Erreur lors du chargement des utilisateurs inactifs');
                }
            } catch (error) {
                console.error('Erreur lors du chargement des utilisateurs inactifs', error);
            }
        },
        async reactivateUser(user) {
            try {
                const token = localStorage.getItem('accessToken');
                const userId = user.id;


                // Faire une requête HTTP PATCH pour réactiver l'utilisateur
                const response = await fetch(`http://localhost:8080/admin/${userId}`, {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },

                });

                // Actualiser la liste des utilisateurs inactifs après la réactivation
                await this.loadInactiveUsers();

                // Vérifiez la réponse de la requête et affichez un message de succès si nécessaire
                console.log('Utilisateur réactivé avec succès :', response);
            } catch (error) {
                console.error('Erreur lors de la réactivation de l\'utilisateur', error);
                // Affichez un message d'erreur si la réactivation échoue
            }
        },
        getUserRole() {
            const token = localStorage.getItem('accessToken');
            if (token) {
                const tokenParts = token.split('.');
                if (tokenParts.length === 3) {
                    const payload = JSON.parse(atob(tokenParts[1]));
                    return payload.role; // Supposons que le rôle de l'utilisateur est stocké dans le champ "role" du payload JWT
                } else {
                    console.error('Token JWT invalide');
                    return null; // Ou renvoyer une valeur par défaut si le token n'est pas valide
                }
            } else {
                console.error('Token JWT introuvable dans le localStorage');
                return null; // Ou renvoyer une valeur par défaut si le token n'est pas présent dans le localStorage
            }
        },
        async changeUserRole(userId) {
            try {
                const token = localStorage.getItem('accessToken');
                if (token) {
                    // Extraire le payload JWT
                    const tokenParts = token.split('.');
                    if (tokenParts.length === 3) {
                        const payload = JSON.parse(atob(tokenParts[1]));
                        // Vérifier si l'utilisateur connecté a le rôle d'administrateur (role === 2)
                        if (payload.role === 2) {
                            const newRole = 1
                            // Effectuer une requête HTTP PATCH pour modifier le rôle de l'utilisateur
                            const response = await fetch(`http://localhost:8080/admin/${userId}/${newRole}`, {
                                method: 'PUT',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'Authorization': `Bearer ${token}`
                                },

                            });
                            if (response.ok) {
                                // Afficher un message de succès
                                console.log('Le rôle de l\'utilisateur a été modifié avec succès');
                            } else {
                                // Afficher un message d'erreur si la requête échoue
                                throw new Error('Erreur lors de la modification du rôle de l\'utilisateur');
                            }
                        } else {
                            // Afficher un message d'erreur si l'utilisateur connecté n'a pas le droit requis
                            throw new Error('Vous n\'avez pas les permissions nécessaires pour effectuer cette action');
                        }
                    } else {
                        // Afficher un message d'erreur si le token JWT est invalide
                        throw new Error('Token JWT invalide');
                    }
                } else {
                    // Afficher un message d'erreur si le token JWT n'est pas trouvé dans le localStorage
                    throw new Error('Token JWT introuvable dans le localStorage');
                }
            } catch (error) {
                console.error('Erreur lors de la modification du rôle de l\'utilisateur :', error);
                // Afficher un message d'erreur à l'utilisateur, par exemple avec un toast ou une alerte
            }
        },
        async deleteEvent(eventId) {
            try {
                const token = localStorage.getItem('accessToken');
                // Envoyer une requête HTTP DELETE pour supprimer l'événement avec l'ID spécifié
                const response = await fetch(`http://localhost:8080/events/${eventId}`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });

                // Vérifier si la suppression a réussi (statut 200)
                if (response.ok) {
                    // Mettre à jour la liste des événements après la suppression
                    this.loadEvents(); // Vous devez implémenter la méthode loadEvents pour charger à nouveau la liste des événements depuis votre API
                    // Afficher un message de succès à l'utilisateur
                    alert('L\'événement a été supprimé avec succès!');
                } else {
                    // En cas d'erreur, afficher un message d'erreur
                    throw new Error('Erreur lors de la suppression de l\'événement');
                }
            } catch (error) {
                console.error('Erreur lors de la suppression de l\'événement:', error);
                // Vous pouvez également afficher un message d'erreur à l'utilisateur ici
            }
        },
        closeModal() {
            // Réinitialiser les données de l'événement en cours d'édition
            this.editedEvent = {};
            // Masquer la modale
            this.showModal = false;
        },
        editEvent(event) {
            // Mettre à jour les données de l'événement en cours d'édition
            this.editedEvent = { ...event };
            // Afficher la modale
            this.showModal = true;
        },
        async saveChanges(eventId) {
            const token = localStorage.getItem('accessToken');
            try {
                // Vérifier si eventId est défini et est un nombre valide
                if (eventId && typeof eventId === 'number' && !isNaN(eventId)) {
                    // Effectuer une requête PATCH pour mettre à jour l'événement
                    const response = await fetch(`http://localhost:8080/events/${eventId}`, {
                        method: 'PATCH',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        },
                        body: JSON.stringify(this.editedEvent),
                    });

                    if (response.ok) {
                        // Mettre à jour l'événement dans la liste des événements après la modification
                        // Vous pouvez implémenter cette partie en fonction de la logique de votre application
                        console.log('Événement modifié avec succès');
                    } else {
                        console.error('Erreur lors de la modification de l\'événement');
                    }
                } else {
                    // Afficher une erreur si eventId n'est pas défini ou n'est pas un nombre valide
                    console.error('Identifiant d\'événement non valide :', eventId);
                }
            } catch (error) {
                console.error('Erreur lors de la modification de l\'événement :', error);
            } finally {
                // Masquer la modale après avoir enregistré les modifications
                this.closeModal();
                await this.loadEvents();
            }
        },



    },
    updateSortBy(value) {
        this.sortBy = value; // Mettre à jour la variable sortBy avec la valeur sélectionnée
        this.handleSort(); // Appeler la méthode handleSort pour effectuer le tri
    },
    updateSortOrder(value) {
        this.sortOrder = value; // Mettre à jour la variable sortOrder avec la valeur sélectionnée
        this.handleSort(); // Appeler la méthode handleSort pour effectuer le tri
    },
    async handleSort() {
        // Vérifier si les options de tri sont sélectionnées
        if (this.sortBy && this.sortOrder) {
            // Copier la liste des utilisateurs pour ne pas modifier l'original
            let sortedUsers = [...this.users];

            // Logique de tri en fonction de l'option sélectionnée dans la première liste déroulante (sortBy)
            switch (this.sortBy) {
                case 'age':
                    sortedUsers.sort((a, b) => {
                        return this.sortOrder === 'asc' ? a.age - b.age : b.age - a.age;
                    });
                    break;
                case 'gender':
                    sortedUsers.sort((a, b) => {
                        return this.sortOrder === 'asc' ? a.gender.localeCompare(b.gender) : b.gender.localeCompare(a.gender);
                    });
                    break;
                case 'weight':
                    sortedUsers.sort((a, b) => {
                        return this.sortOrder === 'asc' ? a.weight - b.weight : b.weight - a.weight;
                    });
                    break;
                // Ajoutez d'autres cas de tri ici si nécessaire
            }

            // Mettre à jour la liste des utilisateurs avec les utilisateurs triés
            this.users = sortedUsers;
        }
    }

};
</script>

